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
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "lib/tsocket/tsocket.h"
#include "lib/stream/packet.h"
#include "libcli/composite/composite.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "libcli/resolve/resolve.h"
#include "librpc/rpc/rpc_common.h"
#include "lib/http/http.h"
#include "lib/util/tevent_ntstatus.h"

struct http_virtual_channel {
	struct tevent_fd *fde;
	struct socket_context *sock;
	struct packet_context *packet;
	struct tstream_context *stream;
	struct tevent_queue *send_queue;
	uint32_t pending_reads;

	uint32_t bytes_sent;					/* Channels are limited and must be recycled */
	bool plugged;
};

struct http_private {
	char *server_name;
	struct http_virtual_channel channel_in;
	struct http_virtual_channel channel_out;
};

struct pipe_open_socket_state {
	struct dcecli_connection *conn;
	struct socket_context *socket_ctx;
	struct http_private *http;
	struct socket_address *localaddr;
	struct socket_address *server;
	const char *target_hostname;
};

struct pipe_open_state {
	const char *server;
	const char *target_hostname;

	uint32_t port;

	struct socket_address *localaddr_in;
	struct socket_address *localaddr_out;
	struct socket_address *srvaddr_in;
	struct socket_address *srvaddr_out;
	const char **addresses;					/* target resolved addresses */
	uint32_t addr_index_in;
	uint32_t addr_index_out;

	struct resolve_context *resolve_ctx;
	struct dcecli_connection *conn;

	struct http_private *http;				/* Protocol control structure */
};

struct open_channel_state
{
	struct http_request *request;
	struct http_request *response;
};

void open_channel_in_done(struct tevent_req *subreq)
{
	struct composite_context *c = tevent_req_callback_data(subreq,
			struct composite_context);
	struct open_channel_state *state = talloc_get_type(c->private_data,
			struct open_channel_state);

	DEBUG(9, ("%s: Retrieving HTTP request status\n", __func__));
	TALLOC_FREE(subreq);
	//c->status = //dcerpc_http_open_channel_in_recv(subreq);
	switch(state->response->response_code) {
	case 200:
		c->status = NT_STATUS_OK;
		break;
	case 401:
		composite_error(c, NT_STATUS_GENERIC_NOT_MAPPED);
		return;
	default:
		composite_error(c, NT_STATUS_GENERIC_NOT_MAPPED);
		return;
	}
	composite_done(c);
}

struct composite_context *dcerpc_http_open_channel_in_send(
		TALLOC_CTX *mem_ctx,
		struct dcecli_connection *conn)
{
	struct composite_context *c;
	struct tevent_req *subreq;
	struct open_channel_state *state;
	struct http_private *http;

	DEBUG(9, ("%s: Opening channel IN\n", __func__));

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, conn->event_ctx);
	if (c == NULL) return NULL;

	state = talloc_zero(c, struct open_channel_state);
	if (composite_nomem(state, c)) return c;
	c->private_data = state;

	/* Assign private state fields */
	http = (struct http_private *)conn->transport.private_data;
	subreq = http_send_request_send(
			mem_ctx,
			conn->event_ctx,
			http->channel_in.stream,
			http->channel_in.send_queue,
			http->server_name,
			HTTP_REQ_RPC_IN_DATA,
			"/rpc/rpcproxy.dll",
			NULL);
	if (composite_nomem(subreq, c)) return c;
	tevent_req_set_callback(subreq, open_channel_in_done, c);

	return c;
}

NTSTATUS dcerpc_http_open_channel_in_recv(struct composite_context *ctx)
{
	return composite_wait_free(ctx);
}

void continue_open_channel_in(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
			struct composite_context);

	DEBUG(9, ("%s: Retrieving open channel IN call status\n", __func__));
	c->status = dcerpc_http_open_channel_in_recv(ctx);
	if (!composite_is_ok(c)) return;
	composite_done(c);
}

/**
 * Called when a IO is triggered by the events system
 */
static void sock_in_io_handler(struct tevent_context *ev, struct tevent_fd *fde,
			    uint16_t flags, void *private_data)
{
	struct dcecli_connection *p = talloc_get_type(private_data,
			struct dcecli_connection);
	struct http_private *http = (struct http_private *)p->transport.private_data;

	if (http->channel_in.sock == NULL) {
		return;
	}
	if (flags & TEVENT_FD_READ) {
		packet_recv(http->channel_in.packet);
	}
}

static void sock_out_io_handler(struct tevent_context *ev, struct tevent_fd *fde,
	    uint16_t flags, void *private_data)
{
	struct dcecli_connection *p = talloc_get_type(private_data,
			struct dcecli_connection);
	struct http_private *http = (struct http_private *)p->transport.private_data;

	if (flags & TEVENT_FD_WRITE) {
		packet_queue_run(http->channel_out.packet);
		return;
	}
}

/**
 * Mark the channel in socket dead
 */
static void sock_in_dead(struct dcecli_connection *p, NTSTATUS status)
{
	struct http_private *http;

	http = (struct http_private *)p->transport.private_data;
	if (!http) return;

	if (http->channel_in.packet) {
		packet_recv_disable(http->channel_in.packet);
		packet_set_fde(http->channel_in.packet, NULL);
		packet_set_socket(http->channel_in.packet, NULL);
	}

	if (http->channel_in.fde) {
		talloc_free(http->channel_in.fde);
		http->channel_in.fde = NULL;
	}

	if (http->channel_in.sock) {
		talloc_free(http->channel_in.sock);
		http->channel_in.sock = NULL;
	}

	if (NT_STATUS_EQUAL(NT_STATUS_UNSUCCESSFUL, status)) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	if (NT_STATUS_EQUAL(NT_STATUS_OK, status)) {
		status = NT_STATUS_END_OF_FILE;
	}

	if (p->transport.recv_data) {
		p->transport.recv_data(p, NULL, status);
	}
}

/**
 * Mark the channel out socket dead
 */
static void sock_out_dead(struct dcecli_connection *p, NTSTATUS status)
{
	struct http_private *http;

	http = (struct http_private *)p->transport.private_data;
	if (!http) return;

	if (http->channel_out.packet) {
		packet_recv_disable(http->channel_out.packet);
		packet_set_fde(http->channel_out.packet, NULL);
		packet_set_socket(http->channel_out.packet, NULL);
	}

	if (http->channel_out.fde) {
		talloc_free(http->channel_out.fde);
		http->channel_out.fde = NULL;
	}

	if (http->channel_out.sock) {
		talloc_free(http->channel_out.sock);
		http->channel_out.sock = NULL;
	}

	if (NT_STATUS_EQUAL(NT_STATUS_UNSUCCESSFUL, status)) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	if (NT_STATUS_EQUAL(NT_STATUS_OK, status)) {
		status = NT_STATUS_END_OF_FILE;
	}
}

/**
 * Shutdown sock pipe connection
 */
static NTSTATUS sock_shutdown_pipe(struct dcecli_connection *p, NTSTATUS status)
{
	struct http_private *http;

	http = (struct http_private *)p->transport.private_data;
	if (http && http->channel_in.sock) {
		sock_in_dead(p, status);
	}
	if (http && http->channel_out.sock) {
		sock_out_dead(p, status);
	}

	return status;
}

/**
 * Initiate a read request
 */
static NTSTATUS sock_send_read(struct dcecli_connection *p)
{
	struct http_private *http;

	http = (struct http_private *)p->transport.private_data;
	http->channel_in.pending_reads++;
	if (http->channel_in.pending_reads == 1) {
		packet_recv_enable(http->channel_in.packet);
	}
	return NT_STATUS_OK;
}

/**
 * Return remote name we make the actual connection
 */
static const char *sock_peer_name(struct dcecli_connection *p)
{
	struct http_private *http;

	http = (struct http_private *)p->transport.private_data;
	return http->server_name;
}

/**
 * Send an initial pdu in a multi-pdu sequence
 */
static NTSTATUS sock_send_request(struct dcecli_connection *p,
		DATA_BLOB *data, bool trigger_read)
{
	struct http_private *http;
	DATA_BLOB blob;
	NTSTATUS status;

	http = (struct http_private *)p->transport.private_data;
	if (http->channel_out.sock == NULL) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	blob = data_blob_talloc(http->channel_out.packet, data->data, data->length);
	if (blob.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = packet_send(http->channel_out.packet, blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (trigger_read) {
		sock_send_read(p);
	}

	return NT_STATUS_OK;
}

/**
 * Return remote name we make the actual connection
 */
static const char *sock_target_hostname(struct dcecli_connection *p)
{
	struct http_private *http;

	http = (struct http_private *)p->transport.private_data;
	return http->server_name;
}

static void continue_socket_in_connect(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
			struct composite_context);
	struct pipe_open_socket_state *s = talloc_get_type(c->private_data,
			struct pipe_open_socket_state);
	struct http_private *http = talloc_get_type(s->http,
			struct http_private);
	struct dcecli_connection *conn = talloc_get_type(s->conn,
			struct dcecli_connection);

	c->status = socket_connect_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		talloc_free(s->socket_ctx);
		DEBUG(0, ("Failed to connect host %s on port %d - %s\n",
			  s->server->addr, s->server->port,
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	DEBUG(9, ("%s: Socket for IN channel opened\n", __func__));

	/* Create the send queue */
	DEBUG(9, ("%s: Creating send queue for IN channel\n", __func__));
	http->channel_in.send_queue = tevent_queue_create(http, "channel IN send queue");
	if (!http->channel_in.send_queue) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		DEBUG(0, ("%s: tevent_queue_create(%s)\n", __func__, nt_errstr(c->status)));
		return;
	}

	/* fill in the transport methods */
	conn->transport.transport    = NCACN_HTTP;
	conn->transport.private_data = http;

	http->server_name = strupper_talloc(http, s->target_hostname);

	http->channel_in.sock = s->socket_ctx;
	http->channel_in.pending_reads = 0;
	http->channel_in.fde = tevent_add_fd(conn->event_ctx, http->channel_in.sock,
			socket_get_fd(http->channel_in.sock), TEVENT_FD_READ,
			sock_in_io_handler, conn);

	conn->transport.recv_data       = NULL;
	conn->transport.send_request    = sock_send_request;
	conn->transport.send_read       = sock_send_read;
	conn->transport.shutdown_pipe   = sock_shutdown_pipe;
	conn->transport.peer_name       = sock_peer_name;
	conn->transport.target_hostname = sock_target_hostname;

	/* Abstract the socket to stream */
	DEBUG(9, ("%s: Creating stream abstraction for IN channel\n", __func__));
	int ret = tstream_bsd_existing_socket(http,
			socket_get_fd(http->channel_in.sock),
			&http->channel_in.stream);
	if (ret == -1) {
		NTSTATUS status = map_nt_error_from_unix_common(errno);
		DEBUG(0, ("%s: failed to setup tstream: %s\n", __func__,
				nt_errstr(status)));
		return;
	}
	socket_set_flags(http->channel_in.sock, SOCKET_FLAG_NOCLOSE);

	/* Initialize packet interface */
	http->channel_in.packet = packet_init(http);
	if (http->channel_in.packet == NULL) {
		talloc_free(s->socket_ctx);
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}

	packet_set_private(http->channel_in.packet, conn);
	packet_set_socket(http->channel_in.packet, http->channel_in.sock);
//	packet_set_callback(http->channel_in.packet, sock_process_recv);
//	packet_set_full_request(http->channel_in.packet, sock_complete_packet);
//	packet_set_error_handler(http->channel_in.packet, sock_error_handler);
//	packet_set_event_context(http->channel_in.packet, conn->event_ctx);
	packet_set_fde(http->channel_in.packet, http->channel_in.fde);
//	packet_set_serialise(http->channel_in.packet);
//	packet_set_initial_read(http->channel_in.packet, 16);

	/* ensure we don't get SIGPIPE */
	BlockSignals(true, SIGPIPE);

	composite_done(c);
}

static void continue_socket_out_connect(struct composite_context *ctx)
{
	struct dcecli_connection *conn;
	struct http_private *http;

	struct composite_context *c = talloc_get_type(ctx->async.private_data,
			struct composite_context);
	struct pipe_open_socket_state *s = talloc_get_type(c->private_data,
			struct pipe_open_socket_state);

	c->status = socket_connect_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		talloc_free(s->socket_ctx);
		DEBUG(0, ("Failed to connect host %s on port %d - %s\n",
			  s->server->addr, s->server->port,
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	DEBUG(9, ("%s: Socket for OUT channel opened\n", __func__));

	/* make it easier to write a function calls */
	conn = s->conn;
	http = s->http;

	/* fill in the transport methods */
	conn->transport.transport    = NCACN_HTTP;
	conn->transport.private_data = http;

	http->channel_out.sock = s->socket_ctx;
	http->channel_out.pending_reads = 0;
	http->channel_out.fde = tevent_add_fd(conn->event_ctx,
			http->channel_out.sock, socket_get_fd(http->channel_out.sock),
			TEVENT_FD_WRITE, sock_out_io_handler, conn);

	conn->transport.recv_data       = NULL;
	conn->transport.send_request    = sock_send_request;
	conn->transport.send_read       = sock_send_read;
	conn->transport.shutdown_pipe   = sock_shutdown_pipe;
	conn->transport.peer_name       = sock_peer_name;
	conn->transport.target_hostname = sock_target_hostname;

	/* Initialize packet interface */
	http->channel_out.packet = packet_init(http);
	if (http->channel_out.packet == NULL) {
		talloc_free(s->socket_ctx);
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}

	packet_set_private(http->channel_out.packet, conn);
	packet_set_socket(http->channel_out.packet, http->channel_out.sock);
//	packet_set_callback(http->channel_in.packet, sock_process_recv);
//	packet_set_full_request(http->channel_in.packet, sock_complete_packet);
//	packet_set_error_handler(http->channel_in.packet, sock_error_handler);
//	packet_set_event_context(http->channel_in.packet, conn->event_ctx);
	packet_set_fde(http->channel_out.packet, http->channel_out.fde);
//	packet_set_serialise(http->channel_in.packet);
//	packet_set_initial_read(http->channel_in.packet, 16);

	/* ensure we don't get SIGPIPE */
	BlockSignals(true, SIGPIPE);

	composite_done(c);
}

static struct composite_context *dcerpc_pipe_open_socket_in_send(
		TALLOC_CTX *mem_ctx,
		struct http_private *http,
		struct dcecli_connection *conn,
		struct socket_address *localaddr,
		struct socket_address *server,
		const char *target_hostname)
{
	struct composite_context *c;
	struct pipe_open_socket_state *s;

	DEBUG(9, ("%s: Opening socket for IN channel\n", __func__));

	c = composite_create(mem_ctx, conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_open_socket_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->conn = conn;
	s->http = http;

	if (localaddr) {
		s->localaddr = talloc_reference(c, localaddr);
		if (composite_nomem(s->localaddr, c)) return c;
	}
	s->server = talloc_reference(c, server);
	if (composite_nomem(s->server, c)) return c;
	s->target_hostname = talloc_reference(s, target_hostname);

	/* Create socket */
	c->status = socket_create(server->family, SOCKET_TYPE_STREAM,
			&s->socket_ctx, 0);
	if (!composite_is_ok(c)) return c;
	talloc_steal(http, s->socket_ctx);

	/* Connect socket */
	struct composite_context *socket_in_connect_req;
	socket_in_connect_req = socket_connect_send(s->socket_ctx, s->localaddr,
			s->server, 0, c->event_ctx);
	composite_continue(c, socket_in_connect_req, continue_socket_in_connect, c);

	return c;
}

static struct composite_context *dcerpc_pipe_open_socket_out_send(
		TALLOC_CTX *mem_ctx,
		struct http_private *http,
		struct dcecli_connection *conn,
		struct socket_address *localaddr,
		struct socket_address *server,
		const char *target_hostname)
{
	struct composite_context *c;
	struct pipe_open_socket_state *s;

	DEBUG(9, ("%s: Opening socket for OUT channel\n", __func__));

	c = composite_create(mem_ctx, conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_open_socket_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->conn = conn;
	s->http = http;

	if (localaddr) {
		s->localaddr = talloc_reference(c, localaddr);
		if (composite_nomem(s->localaddr, c)) return c;
	}
	s->server = talloc_reference(c, server);
	if (composite_nomem(s->server, c)) return c;
	s->target_hostname = talloc_reference(s, target_hostname);

	/* Create socket */
	c->status = socket_create(server->family, SOCKET_TYPE_STREAM,
			&s->socket_ctx, 0);
	if (!composite_is_ok(c)) return c;
	talloc_steal(http, s->socket_ctx);

	/* Connect socket */
	struct composite_context *socket_out_connect_req;
	socket_out_connect_req = socket_connect_send(s->socket_ctx, s->localaddr,
			s->server, 0, c->event_ctx);
	composite_continue(c, socket_out_connect_req, continue_socket_out_connect, c);

	return c;
}

static NTSTATUS dcerpc_pipe_open_socket_in_recv(struct composite_context *c)
{
	return composite_wait_free(c);
}

static NTSTATUS dcerpc_pipe_open_socket_out_recv(struct composite_context *c)
{
	return composite_wait_free(c);
}

static void continue_open_socket_out(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
			struct composite_context);
	struct pipe_open_state *s = talloc_get_type(c->private_data,
			struct pipe_open_state);

	/* receive result socket open request */
	c->status = dcerpc_pipe_open_socket_out_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		/* something went wrong... */
		DEBUG(0, ("Failed to connect host %s (%s) on port %d - %s.\n",
			  s->addresses[s->addr_index_out - 1], s->target_hostname,
			  s->port, nt_errstr(c->status)));
		if (s->addresses[s->addr_index_out]) {
			struct composite_context *open_socket_out_req;
			talloc_free(s->srvaddr_out);
			/* prepare server address using host ip:port and transport name */
			s->srvaddr_out = socket_address_from_strings(s->conn, "ip",
					s->addresses[s->addr_index_out], s->port);
			s->addr_index_out++;
			if (composite_nomem(s->srvaddr_out, c)) return;

			open_socket_out_req = dcerpc_pipe_open_socket_out_send(c, s->http,
					s->conn, s->localaddr_out, s->srvaddr_out,
					s->target_hostname);
			composite_continue(c, open_socket_out_req, continue_open_socket_out, c);
			return;
		} else {
			composite_error(c, c->status);
			return;
		}
	}

	DEBUG(9, ("%s: Sockets opened\n", __func__));

	struct composite_context *open_channel_in;
	open_channel_in = dcerpc_http_open_channel_in_send(c, s->conn);
	composite_continue(c, open_channel_in, continue_open_channel_in, c);
}

static void continue_open_socket_in(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_open_state *s = talloc_get_type(c->private_data,
						   struct pipe_open_state);
	struct composite_context *open_socket_out_req;

	/* receive result socket open request */
	c->status = dcerpc_pipe_open_socket_in_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		/* something went wrong... */
		DEBUG(0, ("Failed to connect host %s (%s) on port %d - %s.\n",
			  s->addresses[s->addr_index_in - 1], s->target_hostname,
			  s->port, nt_errstr(c->status)));
		if (s->addresses[s->addr_index_in]) {
			struct composite_context *open_socket_in_req;
			talloc_free(s->srvaddr_in);
			/* prepare server address using host ip:port and transport name */
			s->srvaddr_in = socket_address_from_strings(s->conn, "ip",
					s->addresses[s->addr_index_in], s->port);
			s->addr_index_in++;
			if (composite_nomem(s->srvaddr_in, c)) return;

			open_socket_in_req = dcerpc_pipe_open_socket_in_send(c, s->http,
					s->conn, s->localaddr_in, s->srvaddr_in,
					s->target_hostname);
			composite_continue(c, open_socket_in_req, continue_open_socket_in, c);
			return;
		} else {
			composite_error(c, c->status);
			return;
		}
	}

	open_socket_out_req = dcerpc_pipe_open_socket_out_send(c, s->http,
			s->conn, s->localaddr_out, s->srvaddr_out, s->target_hostname);
	composite_continue(c, open_socket_out_req, continue_open_socket_out, c);
}

static void continue_http_resolve_name(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
			struct composite_context);
	struct pipe_open_state *s = talloc_get_type(c->private_data,
			struct pipe_open_state);
	struct composite_context *open_socket_in_req;

	DEBUG(9, ("%s: Waiting for resolver\n", __func__));
	c->status = resolve_name_multiple_recv(ctx, s, &s->addresses);
	if (!composite_is_ok(c)) return;

	DEBUG(9, ("%s: Resolved to: %s\n", __func__, s->addresses[0]));

	/* Prepare server address using host ip:port and transport name for channel in socket */
	s->srvaddr_in = socket_address_from_strings(s->conn, "ip",
			s->addresses[s->addr_index_in], s->port);
	if (composite_nomem(s->srvaddr_in, c)) return;
	s->addr_index_in++;
	/* Prepare server address using host ip:port and transport name for channel out socket */
	s->srvaddr_out = socket_address_from_strings(s->conn, "ip",
			s->addresses[s->addr_index_out], s->port);
	if (composite_nomem(s->srvaddr_out, c)) return;
	s->addr_index_out++;

	open_socket_in_req = dcerpc_pipe_open_socket_in_send(c, s->http,
			s->conn, s->localaddr_in, s->srvaddr_in, s->target_hostname);
	composite_continue(c, open_socket_in_req, continue_open_socket_in, c);
}


/**
 * Send rpc pipe open request to given host:port
 */
struct composite_context* dcerpc_pipe_open_http_send(
		struct dcecli_connection *conn,
	    const char *localaddr,
	    const char *server,
	    const char *target_hostname,
	    uint32_t port,
	    struct resolve_context *resolve_ctx)
{
	struct composite_context *c;
	struct pipe_open_state *s;
	struct http_private *http;
	struct composite_context *resolve_req;
	struct nbt_name name;

	DEBUG(9, ("%s: Opening pipe\n", __func__));

	/* composite context allocation and setup */
	c = composite_create(conn, conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_open_state);
    if (composite_nomem(s, c)) return c;
    c->private_data = s;


	http = talloc_zero(conn, struct http_private);
	if (composite_nomem(http, c)) return c;
	s->http = http;

	/* store input parameters in state structure */
	s->server = talloc_strdup(c, server);
	if (composite_nomem(s->server, c)) return c;
	if (target_hostname) {
		s->target_hostname = talloc_strdup(c, target_hostname);
		if (composite_nomem(s->target_hostname, c)) return c;
	}
	s->port = port;
	s->conn = conn;
	s->resolve_ctx = resolve_ctx;
	if (localaddr) {
		s->localaddr_in = socket_address_from_strings(s, "ip", localaddr, 0);
		s->localaddr_out = socket_address_from_strings(s, "ip", localaddr, 0);
		/* if there is no localaddr, we pass NULL for s->localaddr, which is
		 * handled by the socket libraries as meaning no local binding address
		 * specified */
	}

	make_nbt_name_server(&name, server);
	DEBUG(9, ("%s: Resolving\n", __func__));
	resolve_req = resolve_name_send(resolve_ctx, s, &name, c->event_ctx);
	composite_continue(c, resolve_req, continue_http_resolve_name, c);

	return c;
}

NTSTATUS dcerpc_pipe_open_http_recv(struct composite_context *c)
{
	NTSTATUS status;

	status = composite_wait(c);
	talloc_free(c);

	return status;
}
