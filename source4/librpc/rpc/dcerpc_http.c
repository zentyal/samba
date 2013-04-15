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
#include "lib/stream/packet.h"
#include "libcli/composite/composite.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "libcli/resolve/resolve.h"
#include "librpc/rpc/rpc_common.h"

enum http_virtual_channel_type {
	RPC_DATA_IN,
	RPC_DATA_OUT };

enum http_connection_state {
	OPEN_SOCKET_CHANNEL_IN,
	OPEN_SOCKET_CHANNEL_OUT,
	PROTOCOL_INIT,
};

struct http_virtual_channel {
	struct tevent_fd *fde;
	struct socket_context *sock;

	char *server_name;
	struct packet_context *packet;
	uint32_t pending_reads;
	enum http_virtual_channel_type type;
};

struct http_private {
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
	enum http_virtual_channel_type channel;
};

struct pipe_http_state {
	const char *server;
	const char *target_hostname;
	const char **addresses;
	uint32_t index;
	uint32_t port;

	struct socket_address *localaddr;

	struct socket_address *srvaddr;
	struct resolve_context *resolve_ctx;

	struct dcecli_connection *conn;
	enum http_connection_state state;
	struct http_private *http;
};


/**
 * Called when a IO is triggered by the events system
 */
static void sock_in_io_handler(struct tevent_context *ev, struct tevent_fd *fde,
			    uint16_t flags, void *private_data)
{
//	struct dcecli_connection *p = talloc_get_type(private_data,
//						      	  	  	  	  	  struct dcecli_connection);
	//struct http_private *http = talloc_get_type(p->transport.private_data,
	//											struct http_private);
//	struct http_private *http = (struct http_private *)p->transport.private_data;

//	if (flags & TEVENT_FD_WRITE) {
//		packet_queue_run(http->channel_out.packet);
//		return;
//	}
//	fprintf(stderr, "in io handler begin 2\n");
//	if (http->in_channel.sock == NULL) {
//		return;
//	}
//	fprintf(stderr, "in io handler begin 3\n");
//	if (flags & TEVENT_FD_READ) {
//		packet_recv(http->in_channel.packet);
//	}
}


static void continue_socket_connect(struct composite_context *ctx)
{
	struct dcecli_connection *conn;
	struct http_private *http;

	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_open_socket_state *s = talloc_get_type(c->private_data,
							   struct pipe_open_socket_state);

	c->status = socket_connect_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0, ("Failed to connect host %s on port %d - %s\n",
			  s->server->addr, s->server->port,
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	/* make it easier to write a function calls */
	conn = s->conn;
	http = s->http;

	/* fill in the transport methods */
	conn->transport.transport       = NCACN_HTTP;
	conn->transport.private_data    = http;

	switch (s->channel) {
		case RPC_DATA_IN:
			http->channel_in.sock = s->socket_ctx;
			http->channel_in.pending_reads = 0;
			http->channel_in.server_name = strupper_talloc(http, s->target_hostname);
			http->channel_in.fde = tevent_add_fd(conn->event_ctx,
					http->channel_in.sock, socket_get_fd(http->channel_in.sock),
					TEVENT_FD_READ, sock_in_io_handler, conn);
			break;
		case RPC_DATA_OUT:
			http->channel_out.sock = s->socket_ctx;
			http->channel_out.pending_reads = 0;
			http->channel_out.server_name = strupper_talloc(http, s->target_hostname);
			http->channel_out.fde = NULL;
			break;
		default:
			talloc_free(s->socket_ctx);
			composite_error(c, NT_STATUS_INVALID_PARAMETER);
			return;
			break;
	}
	//conn->transport.send_request    = sock_send_request;
	//conn->transport.send_read       = sock_send_read;
	//conn->transport.recv_data       = NULL;
	//conn->transport.shutdown_pipe   = sock_shutdown_pipe;
	//conn->transport.peer_name       = sock_peer_name;
	//conn->transport.target_hostname = sock_target_hostname;

	//sock->packet = packet_init(sock);
	//if (sock->packet == NULL) {
	//	talloc_free(sock);
	//	composite_error(c, NT_STATUS_NO_MEMORY);
	//	return;
	//}

	//packet_set_private(sock->packet, conn);
	//packet_set_socket(sock->packet, sock->sock);
	//packet_set_callback(sock->packet, sock_process_recv);
	//packet_set_full_request(sock->packet, sock_complete_packet);
	//packet_set_error_handler(sock->packet, sock_error_handler);
	//packet_set_event_context(sock->packet, conn->event_ctx);
	//packet_set_fde(sock->packet, sock->fde);
	//packet_set_serialise(sock->packet);
	//packet_set_initial_read(sock->packet, 16);

	/* ensure we don't get SIGPIPE */
	BlockSignals(true, SIGPIPE);

	composite_done(c);
}

static struct composite_context *dcerpc_pipe_open_socket_send(
		TALLOC_CTX *mem_ctx,
		struct http_private *http,
		struct dcecli_connection *conn,
		struct socket_address *localaddr,
		struct socket_address *server,
		const char *target_hostname,
		enum http_connection_state state)
{
	struct composite_context *c;
	struct pipe_open_socket_state *s;

	c = composite_create(mem_ctx, conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_open_socket_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->conn = conn;
	if (localaddr) {
		s->localaddr = talloc_reference(c, localaddr);
		if (composite_nomem(s->localaddr, c)) return c;
	}
	s->server = talloc_reference(c, server);
	if (composite_nomem(s->server, c)) return c;
	s->target_hostname = talloc_reference(s, target_hostname);

	s->http = http;
	switch (state) {
		case OPEN_SOCKET_CHANNEL_IN:
			s->channel = RPC_DATA_IN;
			break;
		case OPEN_SOCKET_CHANNEL_OUT:
			s->channel = RPC_DATA_OUT;
			break;
		default:
			talloc_free(s);
			composite_error(c, NT_STATUS_INVALID_PARAMETER);
			return c;
	}

	/* Create socket */
	c->status = socket_create(server->family, SOCKET_TYPE_STREAM,
			&s->socket_ctx, 0);
	if (!composite_is_ok(c)) return c;
	talloc_steal(http, s->socket_ctx);

	/* Connect socket */
	struct composite_context *conn_req;
	conn_req = socket_connect_send(s->socket_ctx, s->localaddr, s->server, 0,
			c->event_ctx);
	composite_continue(c, conn_req, continue_socket_connect, c);

	return c;
}


static NTSTATUS dcerpc_pipe_open_socket_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);

	talloc_free(c);

	return status;
}

static void continue_open_socket(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_http_state *s = talloc_get_type(c->private_data,
						   struct pipe_http_state);

	/* receive result socket open request */
	c->status = dcerpc_pipe_open_socket_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		/* something went wrong... */
		DEBUG(0, ("Failed to connect host %s (%s) on port %d - %s.\n",
			  s->addresses[s->index - 1], s->target_hostname,
			  s->port, nt_errstr(c->status)));
		if (s->addresses[s->index]) {
			struct composite_context *sock_http_req;
			talloc_free(s->srvaddr);
			/* prepare server address using host ip:port and transport name */
			s->srvaddr = socket_address_from_strings(s->conn, "ip",
					s->addresses[s->index], s->port);
			s->index++;
			if (composite_nomem(s->srvaddr, c)) return;

			sock_http_req = dcerpc_pipe_open_socket_send(c, s->http, s->conn,
					s->localaddr, s->srvaddr, s->target_hostname, s->state);
			composite_continue(c, sock_http_req, continue_open_socket, c);
			return;
		} else {
			composite_error(c, c->status);
			return;
		}
	}

	if (s->state == OPEN_SOCKET_CHANNEL_IN) {
		s->state = OPEN_SOCKET_CHANNEL_OUT;
		struct composite_context *open_socket_req;
		open_socket_req = dcerpc_pipe_open_socket_send(c, s->http, s->conn,
				s->localaddr, s->srvaddr, s->target_hostname, s->state);
		composite_continue(c, open_socket_req, continue_open_socket, c);
		return;
	}

//	if (s->state == OPEN_SOCKET_CHANNEL_OUT) {
//		s->state == PROTOCOL_INIT;
//		struct composite_context *protocol_init_req;
//		protocol_init_req = dcerpc_pipe_protocol_init_send();
//		composite_continue(c, protocol_init_req, continue_protocol_init, c);
//		return;
//	}

	composite_done(c);
}


static void continue_http_resolve_name(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_http_state *s = talloc_get_type(c->private_data,
						   struct pipe_http_state);
	struct composite_context *open_socket_req;

	c->status = resolve_name_multiple_recv(ctx, s, &s->addresses);
	if (!composite_is_ok(c)) return;

	/* prepare server address using host ip:port and transport name */
	s->index = 0;
	s->srvaddr = socket_address_from_strings(s->conn, "ip",
			s->addresses[s->index], s->port);
	if (composite_nomem(s->srvaddr, c)) return;
	s->index++;
	s->state = OPEN_SOCKET_CHANNEL_IN;
	open_socket_req = dcerpc_pipe_open_socket_send(c, s->http, s->conn,
			s->localaddr, s->srvaddr, s->target_hostname, s->state);
	composite_continue(c, open_socket_req, continue_open_socket, c);
}


/*
  Send rpc pipe open request to given host:port using
  tcp/ip transport
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
	struct pipe_http_state *s;
	struct http_private *http;
	struct composite_context *resolve_req;
	struct nbt_name name;

	/* composite context allocation and setup */
	c = composite_create(conn, conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_http_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	http = talloc_zero(conn, struct http_private);
	if (composite_nomem(http, c)) return c;
	s->http = http;

	/* store input parameters in state structure */
	s->server          = talloc_strdup(c, server);
	if (composite_nomem(s->server, c)) return c;
	if (target_hostname) {
		s->target_hostname = talloc_strdup(c, target_hostname);
		if (composite_nomem(s->target_hostname, c)) return c;
	}
	s->port            = port;
	s->conn            = conn;
	s->resolve_ctx     = resolve_ctx;
	if (localaddr) {
		s->localaddr = socket_address_from_strings(s, "ip", localaddr, 0);
		/* if there is no localaddr, we pass NULL for s->localaddr, which is
		 * handled by the socket libraries as meaning no local binding address
		 * specified */
	}

	make_nbt_name_server(&name, server);
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
