/*
   Unix SMB/CIFS implementation.

   RPC over HTTP transport

   Copyright (C) Zentyal S.L. 2013 <scabrero@zentyal.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/tevent/tevent.h"
#include "lib/talloc/talloc.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/util_net.h"
#include "libcli/resolve/resolve.h"
#include "libcli/composite/composite.h"
#include "auth/credentials/credentials.h"

#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"

#include "dcerpc_roh.h"

static NTSTATUS roh_sock_send_request(struct dcecli_connection *p, DATA_BLOB *data, bool trigger_read);
static NTSTATUS roh_sock_send_read(struct dcecli_connection *p);
static NTSTATUS roh_sock_shutdown_pipe(struct dcecli_connection *p, NTSTATUS status);
static const char *roh_sock_peer_name(struct dcecli_connection *p);
static const char *roh_sock_target_hostname(struct dcecli_connection *p);

/**
 *
 */
struct roh_open_connection_state
{
	struct tevent_req *req;
	struct tevent_context *ev;
	struct cli_credentials *credentials;
	struct resolve_context *resolve_ctx;
	const char *server_name;
	unsigned int server_port;

	const char **server_addresses;
	unsigned int server_address_index;

	struct roh_connection *roh;
	struct dcecli_connection *conn;
};

static void roh_continue_resolve_name(struct composite_context *ctx);
static void roh_connect_channel_in_done(struct tevent_req *subreq);

/**
 * Send rpc pipe open request to given host:port
 */
struct tevent_req* dcerpc_pipe_open_roh_send(
		TALLOC_CTX *mem_ctx,
		struct dcecli_connection *conn,
		struct tevent_context *ev,
		struct resolve_context *resolve_ctx,
		struct cli_credentials *credentials,
	    const char *target,
	    unsigned int target_port,
	    bool use_https,
	    bool use_client_certificate)
{
	struct tevent_req *req;
	struct composite_context *ctx;
	struct roh_open_connection_state *state;
	struct nbt_name name;

	DEBUG(8, ("%s: Connecting, target %s, HTTPS: %s, client certificate: %s\n",
			__func__, target, use_https ? "true" : "false",
					use_client_certificate ? "true" : "false"));

	req = tevent_req_create(mem_ctx, &state, struct roh_open_connection_state);
	if (req == NULL)
		return NULL;

	/* Authentication based on certificates is not yet supported */
	if (use_client_certificate) {
		tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
		return tevent_req_post(req, ev);
	}

	/* Set state fields */
	state->req = req;
	state->ev = ev;
	state->credentials = credentials;
	state->server_name = talloc_strdup(state, target);
	state->server_port = target_port;
	state->conn = conn;

	/* Initialize connection structure (3.2.1.3) */
	/* TODO Initialize virtual connection cookie table? */
	state->roh = talloc_zero(mem_ctx, struct roh_connection);
	state->roh->server_name = talloc_strdup(state->roh, target);
	state->roh->ev = ev;
	state->roh->timeout_seconds = ROH_DEFAULT_TIMEOUT;
	state->roh->protocol_version = ROH_V2;
	state->roh->connection_state = ROH_STATE_OPEN_START;
	state->roh->connection_cookie = GUID_random();
	state->roh->association_group_id_cookie = GUID_random();

	/* Additional initialization steps (3.2.2.3) */
	state->roh->proxy_use = false;
	state->roh->current_keep_alive_time = 0;
	state->roh->current_keep_alive_interval = 0;

	/* Resolve RPC proxy server name asynchronously */
	make_nbt_name_server(&name, state->server_name);
	ctx = resolve_name_send(resolve_ctx, state, &name, state->ev);
	if (tevent_req_nomem(ctx, req)) {
		return tevent_req_post(req, ev);
	}
	ctx->async.fn = roh_continue_resolve_name;
	ctx->async.private_data = state;

	return req;
}

NTSTATUS dcerpc_pipe_open_roh_recv(struct tevent_req *req)
{
	NTSTATUS status;

	DEBUG(8, ("%s\n", __func__));
	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

/**
 * Handle name lookup reply
 */
static void roh_continue_resolve_name(struct composite_context *ctx)
{
	struct roh_open_connection_state *state;
	NTSTATUS status;
	unsigned int i;
	struct tevent_req *subreq;

	state = talloc_get_type_abort(ctx->async.private_data,
			struct roh_open_connection_state);
	status = resolve_name_multiple_recv(ctx, state, &state->server_addresses);
	if (tevent_req_nterror(state->req, status)) {
		DEBUG(2, ("%s: No server found: %s\n", __func__, nt_errstr(status)));
		return;
	}
	for (i=0; state->server_addresses[i]; i++) {
		DEBUG(4, ("%s: Response %u at '%s'\n", __func__, i, state->server_addresses[i]));
	}
	state->server_address_index = 0;

	if (state->server_addresses[state->server_address_index] == NULL) {
		tevent_req_nterror(state->req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		DEBUG(2, ("%s: No server found\n", __func__));
		return;
	}

	/* TODO Determine proxy use */

	state->roh->connection_state = ROH_STATE_OPEN_START;
	subreq = roh_connect_channel_in_send(state, state->ev, state->server_name,
			state->server_addresses[state->server_address_index],
			state->server_port, state->credentials, state->roh);
	if (tevent_req_nomem(subreq, state->req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_connect_channel_in_done, state->req);
}

static void roh_connect_channel_out_done(struct tevent_req *subreq);
static void roh_connect_channel_in_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	status = roh_connect_channel_in_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_connect_channel_out_send(state, state->ev, state->server_name,
				state->server_addresses[state->server_address_index],
				state->server_port, state->credentials, state->roh);
	if (tevent_req_nomem(subreq, state->req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_connect_channel_out_done, state->req);
}

static void roh_send_RPC_DATA_IN_done(struct tevent_req *subreq);
static void roh_connect_channel_out_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	status = roh_connect_channel_out_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_send_RPC_DATA_IN_send(state, state->ev, state->server_name, state->server_port, state->credentials, state->roh);
	tevent_req_set_callback(subreq, roh_send_RPC_DATA_IN_done, req);
}

static void roh_send_RPC_DATA_OUT_done(struct tevent_req *subreq);
static void roh_send_RPC_DATA_IN_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	status = roh_send_RPC_DATA_IN_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_send_RPC_DATA_OUT_send(state, state->ev, state->server_name, state->server_port, state->credentials, state->roh);
	tevent_req_set_callback(subreq, roh_send_RPC_DATA_OUT_done, req);
}

static void roh_send_CONN_A1_done(struct tevent_req *subreq);
static void roh_send_RPC_DATA_OUT_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	status = roh_send_RPC_DATA_OUT_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_send_CONN_A1_send(state, state->ev, state->roh);
	tevent_req_set_callback(subreq, roh_send_CONN_A1_done, req);
}

static void roh_send_CONN_B1_done(struct tevent_req *subreq);
static void roh_send_CONN_A1_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	status = roh_send_CONN_B1_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_send_CONN_B1_send(state, state->ev, state->roh);
	tevent_req_set_callback(subreq, roh_send_CONN_B1_done, req);
}

static void roh_recv_out_channel_response_done(struct tevent_req *subreq);
static void roh_send_CONN_B1_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	status = roh_send_CONN_A1_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->roh->connection_state = ROH_STATE_OUT_CHANNEL_WAIT;
	subreq = roh_recv_out_channel_response_send(state, state->ev, state->roh);
	tevent_req_set_callback(subreq, roh_recv_out_channel_response_done, req);
}

static void roh_recv_CONN_A3_done(struct tevent_req *subreq);
static void roh_recv_out_channel_response_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	char *response;
	status = roh_recv_out_channel_response_recv(subreq, state, &response);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->roh->connection_state = ROH_STATE_WAIT_A3W;
	subreq = roh_recv_CONN_A3_send(state, state->ev, state->roh);
	tevent_req_set_callback(subreq, roh_recv_CONN_A3_done, req);
}

static void roh_recv_CONN_C2_done(struct tevent_req *subreq);
static void roh_recv_CONN_A3_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	status = roh_recv_CONN_A3_recv(subreq,
			&state->roh->default_channel_out->connection_timeout);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->roh->connection_state = ROH_STATE_WAIT_C2;
	subreq = roh_recv_CONN_C2_send(state, state->ev, state->roh);
	tevent_req_set_callback(subreq, roh_recv_CONN_C2_done, req);
}

static void roh_recv_CONN_C2_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct roh_open_connection_state *state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	NTSTATUS status;
	unsigned int version, recv, timeout;
	status = roh_recv_CONN_C2_recv(subreq, &version, &recv, &timeout);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->roh->connection_state = ROH_STATE_OPENED;

	/* Fill in the transport methods */
	state->conn->transport.transport    = NCACN_HTTP;
	state->conn->transport.private_data = state->roh;

	//	http->channel_in.fde = tevent_add_fd(conn->event_ctx, http->channel_in.sock,
	//			socket_get_fd(http->channel_in.sock), TEVENT_FD_READ,
	//			sock_in_io_handler, conn);

	state->conn->transport.recv_data       = NULL;
	state->conn->transport.send_request    = roh_sock_send_request;
	state->conn->transport.send_read       = roh_sock_send_read;
	state->conn->transport.shutdown_pipe   = roh_sock_shutdown_pipe;
	state->conn->transport.peer_name       = roh_sock_peer_name;
	state->conn->transport.target_hostname = roh_sock_target_hostname;

	tevent_req_done(req);
}

static NTSTATUS roh_sock_send_request(struct dcecli_connection *p,
		DATA_BLOB *blob, bool trigger_read)
{
	struct roh_connection *roh;
	int bytes_written, sys_errno;

	DEBUG(8, ("%s: Length: %d bytes, trigger_read: %s\n", __func__,
			(int)blob->length, trigger_read ? "true":"false"));
	roh = talloc_get_type_abort(p->transport.private_data, struct roh_connection);

	if (roh->default_channel_in == NULL) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	struct iovec iov;
	iov.iov_base = (void *)blob->data;
	iov.iov_len = blob->length;
	struct tevent_req *req = tstream_writev_queue_send(
			roh->default_channel_in,
			roh->ev,
			roh->default_channel_in->stream,
			roh->default_channel_in->send_queue,
			&iov, 1);
	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	bool ok = tevent_req_poll(req, p->event_ctx);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	bytes_written = tstream_writev_queue_recv(req, &sys_errno);
	if (bytes_written <= 0) {
		DEBUG(0, ("%s: error: %s (%d)\n", __func__, strerror(sys_errno), sys_errno));
		return map_nt_error_from_unix_common(sys_errno);
	}
	/* Update sent bytes */
	roh->default_channel_in->sent_bytes += bytes_written;

	if (trigger_read) {
		roh_sock_send_read(p);
	}

	return NT_STATUS_OK;
}

static NTSTATUS roh_sock_send_read(struct dcecli_connection *p)
{
	struct roh_connection *roh;

	DEBUG(8, ("%s\n", __func__));
	roh = talloc_get_type_abort(p->transport.private_data, struct roh_connection);

	struct tevent_req *req = dcerpc_read_ncacn_packet_send(roh, roh->ev,
				roh->default_channel_out->stream);
	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	bool ok = tevent_req_poll(req, p->event_ctx);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	struct ncacn_packet *pkt;
	DATA_BLOB buffer;
	NTSTATUS status;

	status = dcerpc_read_ncacn_packet_recv(req, roh, &pkt, &buffer);
	TALLOC_FREE(req);
	if (tevent_req_nterror(req, status)) {
		DEBUG(0, ("%s: Error receiving packet\n", __func__));
		return status;
	}

	p->transport.recv_data(p, &buffer, NT_STATUS_OK);

	return NT_STATUS_OK;
}

static NTSTATUS roh_sock_shutdown_pipe(struct dcecli_connection *p, NTSTATUS status)
{
	struct roh_connection *roh;

	DEBUG(8, ("%s\n", __func__));
	roh = talloc_get_type_abort(p->transport.private_data, struct roh_connection);

//	if (http && http->channel_in.sock) {
//		sock_in_dead(p, status);
//	}
//	if (http && http->channel_out.sock) {
//		sock_out_dead(p, status);
//	}
//
//	return status;
	return NT_STATUS_OK;
}

static const char *roh_sock_peer_name(struct dcecli_connection *p)
{
	struct roh_connection *roh;

	DEBUG(8, ("%s\n", __func__));
	roh = talloc_get_type_abort(p->transport.private_data, struct roh_connection);
	return roh->server_name;
}

static const char *roh_sock_target_hostname(struct dcecli_connection *p)
{
	struct roh_connection *roh;

	DEBUG(8, ("%s\n", __func__));
	roh = talloc_get_type_abort(p->transport.private_data, struct roh_connection);
	return roh->server_name;
}
