/*
   Unix SMB/CIFS implementation.

   HTTP library

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
#include <talloc_dict.h>
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "http.h"
#include "lib/tsocket/tsocket.h"
#include "util/tevent_werror.h"
#include <sys/uio.h>
#include "lib/util/dlinklist.h"

enum http_parser_state {
	HTTP_READING_FIRSTLINE,	/**< reading Request-Line (incoming conn) or
	 	 	 	 	 	 	 **< Status-Line (outgoing conn) */
	HTTP_READING_HEADERS,	/**< reading request/response headers */
	HTTP_READING_BODY,		/**< reading request/response body */
	HTTP_READING_TRAILER,	/**< reading request/response chunked trailer */
	HTTP_READING_DONE,
};

enum http_read_status {
	HTTP_ALL_DATA_READ,
	HTTP_MORE_DATA_EXPECTED,
	HTTP_DATA_CORRUPTED,
	HTTP_REQUEST_CANCELED,
	HTTP_DATA_TOO_LONG,
};

struct http_read_response_state {
	struct tevent_context *ev;
	struct tstream_context *stream;

	enum http_parser_state parser_state;

	size_t max_headers_size;

	DATA_BLOB buffer;
	struct http_request *request;
};

struct http_send_request_state {
	struct tevent_context *ev;
	struct tstream_context *stream;

	DATA_BLOB buffer;
	struct iovec iov;
	struct http_request *request;
	ssize_t nwritten;
};

struct http_header {
	struct http_header *next, *prev;
	const char *key;
	const char *value;
};

static NTSTATUS http_push_request(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, struct http_request *req);
static void http_send_request_done(struct tevent_req *subreq);

static void http_read_response_done(struct tevent_req *subreq);

static int http_remove_header(struct http_header **headers, const char *key);
static int http_add_header(TALLOC_CTX *mem_ctx, struct http_header **headers, const char *key, const char *value);
static int http_add_header_internal(TALLOC_CTX *mem_ctx, struct http_header **headers, const char *key, const char *value);
static int http_header_is_valid_value(const char *value);
#if 0
static enum read_status http_parse_headers(struct http_read_response_state *state)
{
	enum message_read_status errcode = DATA_CORRUPTED;
	enum message_read_status status = MORE_DATA_EXPECTED;
	char *line;

	struct http_header *headers = state->request->response_headers;
	size_t line_length;
	while ((line = evbuffer_readln(buffer, &line_length, EVBUFFER_EOL_CRLF)) != NULL) {
		char *skey, *svalue;

		state->request->headers_size += line_length;

		if (state->request->headers_size > state->max_headers_size) {
			errcode = DATA_TOO_LONG;
			goto error;
		}

		if (*line == '\0') { /* Last header - Done */
			status = ALL_DATA_READ;
			//mm_free(line);
			break;
		}

		/* Check if this is a continuation line */
		if (*line == ' ' || *line == '\t') {
			if (http_append_to_last_header(headers, line) == -1)
				goto error;
			//mm_free(line);
			continue;
		}

		/* Processing of header lines */
		svalue = line;
		skey = strsep(&svalue, ":");
		if (svalue == NULL)
			goto error;

		svalue += strspn(svalue, " ");
		evutil_rtrim_lws_(svalue);

		if (http_add_header(headers, skey, svalue) == -1)
			goto error;

		mm_free(line);
	}

	if (status == MORE_DATA_EXPECTED) {
		if (state->request->headers_size + evbuffer_get_length(buffer) > state->max_headers_size)
			return DATA_TOO_LONG;
	}

	return status;

 error:
	//mm_free(line);
	return errcode;
}

static void http_read_header(struct http_read_response_state *state, struct http_request *req)
{
	enum read_status res;

	res = http_parse_headers();
	if (res == DATA_CORRUPTED || res == DATA_TOO_LONG) {
		/* Error while reading, terminate */
		DEBUG(0, ("%s: Bad header lines\n", __func__));
		// TODO evhttp_connection_fail_(evcon, EVCON_HTTP_INVALID_HEADER);
		return;
	} else if (res == MORE_DATA_EXPECTED) {
		/* Need more header lines */
		return;
	}

	/* Disable reading for now */
	// bufferevent_disable(evcon->bufev, EV_READ);

	/* Done reading headers, do the real work */
	switch (state->request->kind) {
		case HTTP_REQUEST:
			DEBUG(9, ("%s: Checking for post data\n", __func__));
			http_get_body();
			break;
		case HTTP_RESPONSE:
			/* Start over if we got a 100 Continue response. */
			if (state->request->response_code == 100) {
				http_start_read();
				return;
			}
			if (!http_response_needs_body(req)) {
				DEBUG(9, ("%s: Skipping body for code %d\n",
						__func__, state->request->response_code));
				http_connection_done();
			} else {
				DEBUG(9, ("%s: Start of read body for %s\n", __func__, req->remote_host));
				http_get_body();
			}
			break;
		default:
			DEBUG(0, ("%s: Bad header\n", __func__));
			// TODO http_connection_fail_(evcon, EVCON_HTTP_INVALID_HEADER);
			break;
	}
}
#endif

/**
 * Determines if a response should have a body.
 * Follows the rules in RFC 2616 section 4.3.
 * @return 1 if the response MUST have a body; 0 if the response MUST NOT have
 *     a body.
 */
static int http_response_needs_body(struct http_request *req)
{
	return (req->response_code != HTTP_NOCONTENT &&
		req->response_code != HTTP_NOTMODIFIED &&
		(req->response_code < 100 || req->response_code >= 200) &&
		req->type != HTTP_REQ_HEAD);
}

/**
 * Parses the HTTP headers
 */
static enum http_read_status http_parse_headers(struct http_read_response_state *state)
{
	enum http_read_status status = HTTP_ALL_DATA_READ;
	char *line = (char *)(state->buffer.data);
	char *ptr = NULL;

	DEBUG(10, ("%s: Buffer (%zi) '%s'\n", __func__, state->buffer.length, line));

	if (state->buffer.length > state->max_headers_size) {
		DEBUG(0, ("%s: Headers too long: %zi, maximum length is %zi\n", __func__,
				state->buffer.length, state->max_headers_size));
		return HTTP_DATA_TOO_LONG;
	}

	ptr = strstr(line, "\r\n");
	if (ptr == NULL) {
		return HTTP_MORE_DATA_EXPECTED;
	}

	state->request->headers_size += state->buffer.length;

	if (strncasecmp(line, "\r\n", 2) == 0) {
		DEBUG(9,("%s: All headers read\n", __func__));
		/* Done reading headers, do the real work */
		switch (state->request->kind) {
//			case HTTP_REQUEST:
//				DEBUG(9, ("%s: Checking for post data\n", __func__));
//				http_get_body(state);
//				break;
			case HTTP_RESPONSE:
//				if (state->request->response_code == 100) {
//					/* Start over if we got a 100 Continue response. */
//					http_start_read(state);
//					return;
//				}
				if (!http_response_needs_body(state->request)) {
					DEBUG(9, ("%s: Skipping body for code %d\n", __func__,
							state->request->response_code));
					// http_connection_done(state);
				} else {
					DEBUG(9, ("%s: Start of read body\n", __func__));
					// TODO http_get_body(state);
				}
				state->parser_state = HTTP_READING_TRAILER;
				break;
			default:
				DEBUG(0, ("%s: Bad header\n", __func__));
				//http_connection_fail_(evcon, EVCON_HTTP_INVALID_HEADER);
				break;
		}
		return HTTP_ALL_DATA_READ;
	}

	char *key = NULL;
	char *value = NULL;
	int n = sscanf(line, "%a[^:]: %a[^\r\n]\r\n", &key, &value);
	if (n != 2) {
		DEBUG(0, ("%s: Error parsing header '%s'\n", __func__, line));
		free(key);
		free(value);
		return HTTP_DATA_CORRUPTED;
	}

	if (http_add_header(state, &state->request->response_headers, key, value) == -1) {
		return HTTP_DATA_CORRUPTED;
	}
	free(key);
	free(value);

	return status;
}

/**
 * Parses the first line of a HTTP response
 */
static bool http_parse_response_line(struct http_read_response_state *state)
{
	char *protocol, *msg;
	char major, minor;
	int code;
	char *line = (char *)(state->buffer.data);

	int n = sscanf(line, "%a[^/]/%c.%c %d %a[^\r\n]\r\n",
			&protocol, &major, &minor, &code, &msg);
	DEBUG(9, ("%s: Header parsed(%i): protocol->%s, major->%c, minor->%c, "
			"code->%d, message->%s\n", __func__, n, protocol, major, minor,
			code, msg));
	if (n != 5) {
		DEBUG(0, ("%s: Error parsing header\n",	__func__));
		return false;
	}
	if (major != '1') {
		DEBUG(0, ("%s: Bad HTTP major number '%c'\n", __func__, major));
		return false;
	}
	if (code == 0) {
		DEBUG(0, ("%s: Bad response code '%d'", __func__, code));
		return false;
	}
	state->request->major = major;
	state->request->minor = minor;
	state->request->response_code = code;
	state->request->response_phrase = talloc_strdup(state, msg);
	free(protocol);
	free(msg);

	return true;
}

/*
 * Parses header lines from a request or a response into the specified
 * request object given a buffer.
 *
 * Returns
 *   HTTP_DATA_CORRUPTED		on error
 *   HTTP_MORE_DATA_EXPECTED	when we need to read more headers
 *   HTTP_DATA_TOO_LONG			on error
 *   HTTP_ALL_DATA_READ			when all headers have been read
 */

static enum http_read_status http_parse_firstline(struct http_read_response_state *state)
{
	enum http_read_status status = HTTP_ALL_DATA_READ;
	char *line = (char *)(state->buffer.data);
	char *ptr = NULL;

	DEBUG(10, ("%s: Buffer (%zi) '%s'\n", __func__, state->buffer.length, line));

	if (state->buffer.length > state->max_headers_size) {
		DEBUG(0, ("%s: Headers too long: %zi, maximum length is %zi\n", __func__,
				state->buffer.length, state->max_headers_size));
		return HTTP_DATA_TOO_LONG;
	}

	ptr = strstr(line, "\r\n");
	if (ptr == NULL) {
		return HTTP_MORE_DATA_EXPECTED;
	}

	state->request->headers_size = state->buffer.length;
	switch (state->request->kind) {
//		case HTTP_REQUEST:
//			if (http_parse_request_line(state, line) == -1)
//				status = DATA_CORRUPTED;
//			break;
		case HTTP_RESPONSE:
			if (!http_parse_response_line(state))
				status = HTTP_DATA_CORRUPTED;
			break;
		default:
			status = HTTP_DATA_CORRUPTED;
			break;
	}

	/* Next state, read HTTP headers */
	state->parser_state = HTTP_READING_HEADERS;

	return status;
}

static enum http_read_status http_parse_buffer(
		struct http_read_response_state *state)
{
	switch (state->parser_state) {
		case HTTP_READING_FIRSTLINE:
			return http_parse_firstline(state);
		case HTTP_READING_HEADERS:
			return http_parse_headers(state);
		case HTTP_READING_BODY:
			//evhttp_read_body(state, &blob);
			break;
		case HTTP_READING_TRAILER:
			//evhttp_read_trailer(state, &blob);
			break;
		default:
			DEBUG(0, ("%s: Illegal parser state %d", __func__, state->parser_state));
			break;
	}
	return HTTP_DATA_CORRUPTED;
}

static int http_read_response_next_vector(
		struct tstream_context *stream,
		void *private_data,
		TALLOC_CTX *mem_ctx,
		struct iovec **_vector,
		size_t *_count)
{
	struct http_read_response_state *state;
	struct iovec *vector;

	state =	talloc_get_type_abort(private_data,
			struct http_read_response_state);
	vector = talloc_array(mem_ctx, struct iovec, 1);
	if (!vector) {
		return -1;
	}

	if (state->buffer.data == NULL) {
		/* Allocate buffer */
		state->buffer.data = talloc_zero_array(state, uint8_t, 1);
		if (!state->buffer.data) {
			return -1;
		}
		state->buffer.length = 1;

		/* Return now, nothing to parse yet */
		vector[0].iov_base = (void *)(state->buffer.data);
		vector[0].iov_len = 1;
		*_vector = vector;
		*_count = 1;
		return 0;
	}

	switch (http_parse_buffer(state)) {
		case HTTP_ALL_DATA_READ:
			if (state->parser_state == HTTP_READING_TRAILER) {
				/* Full request or response parsed */
				*_vector = NULL;
				*_count = 0;
			} else {
				/* Free current buffer and allocate new one */
				TALLOC_FREE(state->buffer.data);
				state->buffer.data = talloc_zero_array(state, uint8_t, 1);
				if (!state->buffer.data) {
					return -1;
				}
				state->buffer.length = 1;

				vector[0].iov_base = (void *)(state->buffer.data);
				vector[0].iov_len = 1;
				*_vector = vector;
				*_count = 1;
			}
			break;
		case HTTP_MORE_DATA_EXPECTED:
			/* TODO Optimize, allocating byte by byte */
			state->buffer.data = talloc_realloc(state, state->buffer.data,
					uint8_t, state->buffer.length + 1);
			if (!state->buffer.data) {
				return -1;
			}
			state->buffer.length++;
			vector[0].iov_base = (void *)(state->buffer.data +
					state->buffer.length - 1);
			vector[0].iov_len = 1;
			*_vector = vector;
			*_count = 1;
			break;
		case HTTP_DATA_CORRUPTED:
		case HTTP_REQUEST_CANCELED:
		case HTTP_DATA_TOO_LONG:
			return -1;
			break;
		default:
			DEBUG(0, ("%s: Unexpected status\n", __func__));
			break;
	}
	return 0;
}

static void tstream_readv_pdu_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				struct tevent_req);
	struct http_read_response_state *state = tevent_req_data(req,
				struct http_read_response_state);

	DEBUG(9, ("%s: Response fully retrieved\n", __func__));
	talloc_free(subreq);
	tevent_req_done(req);
}

/**
 * Waits for request response
 */
struct tevent_req *http_read_response_send(TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct tstream_context *stream)
{
	struct tevent_req *req, *subreq;
	struct http_read_response_state *state;

	DEBUG(9, ("%s: Reading HTTP response\n", __func__));

	req = tevent_req_create(mem_ctx, &state, struct http_read_response_state);
	if (req == NULL)
		return NULL;

	state->ev = ev;
	state->stream = stream;

	state->max_headers_size = HTTP_MAX_HEADER_SIZE;
	state->parser_state = HTTP_READING_FIRSTLINE;
	state->request = talloc_zero(state, struct http_request);
	if (tevent_req_nomem(state->request, req)) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return tevent_req_post(req, ev);
	}
	state->request->kind = HTTP_RESPONSE;

	subreq = tstream_readv_pdu_send(state, ev,
			stream,
			http_read_response_next_vector,
			state);
	if (tevent_req_nomem(subreq,req)) {
		tevent_req_post(req, ev);
		return req;
	}
	tevent_req_set_callback(subreq, tstream_readv_pdu_done, req);

	return req;
}

/**
 * Build a HTTP request, send it and get the response
 */
struct tevent_req *http_send_request_send(TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct tstream_context *stream,
		struct tevent_queue *send_queue,
		const char *remote_host,
		enum http_cmd_type type,
		const char *uri,
		DATA_BLOB *data)
{
	struct tevent_req *req, *subreq;
	struct http_send_request_state *state;
	NTSTATUS status;

	DEBUG(9, ("%s: Sending HTTP request\n", __func__));

	req = tevent_req_create(mem_ctx, &state, struct http_send_request_state);
	if (req == NULL)
		return NULL;

	state->request = talloc_zero(state, struct http_request);
	if (tevent_req_nomem(state->request, req)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}

	state->ev = ev;
	state->stream = stream;

	state->request->headers_size = 0;
	state->request->body_size = 0;
	state->request->major = '1';
	state->request->minor = '1';
	state->request->kind = HTTP_REQUEST;
	state->request->type = type;
	state->request->uri = talloc_strdup(state, uri);
	state->request->remote_host = talloc_strdup(state, remote_host);
	state->request->request_headers = NULL;
	state->request->response_headers = NULL;
	state->request->output_buffer = data;
	talloc_steal(state, data);

	// Push the request to a data blob
	status = http_push_request(state, &state->buffer, state->request);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req,ev);
	}

	state->iov.iov_base = (char *) state->buffer.data;
	state->iov.iov_len = state->buffer.length;
	subreq = tstream_writev_queue_send(state, ev, stream,
				send_queue, &state->iov, 1);
	if (tevent_req_nomem(subreq, req)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, http_send_request_done, req);

	return req;
}

static void http_read_response_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				struct tevent_req);
	struct http_read_response_state *state = tevent_req_data(req,
				struct http_read_response_state);


	DEBUG(9, ("%s\n", __func__));
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static void http_send_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
			struct tevent_req);
	struct http_send_request_state *state = tevent_req_data(req,
			struct http_send_request_state);
	int err;

	state->nwritten = tstream_writev_queue_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (state->nwritten == -1 && err != 0) {
		tevent_req_werror(req, unix_to_werror(err));
		// TODO ¿Disconnect?
		return;
	}

	DEBUG(9, ("%s: Request sent, waiting for response\n", __func__));

	/* Wait for server response */
	subreq = http_read_response_send(state, state->ev, state->stream);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, http_read_response_done, req);
	return;
}

/***************************************/

/** Given an evhttp_cmd_type, returns a constant string containing the
 * equivalent HTTP command, or NULL if the evhttp_command_type is
 * unrecognized. */
static const char *http_method(enum http_cmd_type type)
{
	const char *method;

	switch (type) {
	case HTTP_REQ_RPC_IN_DATA:
		method = "RPC_IN_DATA";
		break;
	case HTTP_REQ_RPC_OUT_DATA:
		method = "RPC_OUT_DATA";
		break;
	default:
		method = NULL;
		break;
	}

	return method;
}

/* Create the headers needed for an outgoing HTTP request, adds them to
 * the request's header list, and writes the request line to the
 * output buffer.
 */
static void http_make_header_request(TALLOC_CTX *mem_ctx, DATA_BLOB *buffer,
		struct http_request *req)
{
	const char *method;

	http_remove_header(&req->request_headers, "Proxy-Connection");

	/* Generate request line */
	method = http_method(req->type);
	const char *str = talloc_asprintf(mem_ctx, "%s %s HTTP/%c.%c\r\n", method,
			req->uri, req->major, req->minor);
	data_blob_append(mem_ctx, buffer, str, strlen(str));

	/* Add the content length on a post or put request if missing */
//	if ((req->type == EVHTTP_REQ_POST || req->type == EVHTTP_REQ_PUT) &&
//			evhttp_find_header(req->output_headers, "Content-Length") == NULL){
//		char size[22];
//		evutil_snprintf(size, sizeof(size), EV_SIZE_FMT,
//		    EV_SIZE_ARG(evbuffer_get_length(req->output_buffer)));
//		evhttp_add_header(req->output_headers, "Content-Length", size);
//	}

	http_add_header(mem_ctx, &req->request_headers, "Accept", "application/rpc");
	http_add_header(mem_ctx, &req->request_headers, "User-Agent", "MSRPC");
	http_add_header(mem_ctx, &req->request_headers, "Host", req->remote_host);
	http_add_header(mem_ctx, &req->request_headers, "Connection", "keep-alive");
	http_add_header(mem_ctx, &req->request_headers, "Cache-Control", "no-cache");
	http_add_header(mem_ctx, &req->request_headers, "Content-Length", "0");
}

/**
 * Generate all headers appropriate for sending the http request in req (or
 * the response, if we're sending a response), and write them to evcon's
 * bufferevent. Also writes all data from req->output_buffer
 */
static NTSTATUS http_make_header(TALLOC_CTX *mem_ctx, DATA_BLOB *blob,
		struct http_request *req)
{
	struct http_header *header;

	/*
	 * Depending if this is a HTTP request or response, we might need to
	 * add some new headers or remove existing headers.
	 */
	if (req->kind == HTTP_REQUEST) {
		http_make_header_request(mem_ctx, blob, req);
	} else {
		//http_make_header_response(mem_ctx, req, blob);
	}

	for (header=req->request_headers; header != NULL; header=header->next) {
		const char *header_str = talloc_asprintf(mem_ctx, "%s: %s\r\n",
				header->key, header->value);
		size_t len = strlen(header_str);
		if (!data_blob_append(mem_ctx, blob, header_str, len)) {
			return NT_STATUS_NO_MEMORY;
		}
	}


	if (!data_blob_append(mem_ctx, blob, "\r\n",2)) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Add request body */
	if (req->output_buffer != NULL && req->output_buffer->length > 0) {
		if (!data_blob_append(mem_ctx, blob, req->output_buffer->data,
				req->output_buffer->length)) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	return NT_STATUS_OK;
}

/*
 * Returns 0,  if the header was successfully removed.
 * Returns -1, if the header could not be found.
 */
static int http_remove_header(struct http_header **headers, const char *key)
{
	struct http_header *header;

	for(header = *headers; header != NULL; header = header->next) {
		if (strcmp(key, header->key) == 0) {
			DLIST_REMOVE(*headers, header);
			return 0;
		}
	}
	return -1;
}

static int http_add_header(TALLOC_CTX *mem_ctx, struct http_header **headers,
		const char *key, const char *value)
{
	if (strchr(key, '\r') != NULL || strchr(key, '\n') != NULL) {
		DEBUG(0, ("%s: Dropping illegal header key\n", __func__));
		return -1;
	}

	if (!http_header_is_valid_value(value)) {
		DEBUG(0, ("%s: Dropping illegal header value\n", __func__));
		return -1;
	}

	return (http_add_header_internal(mem_ctx, headers, key, value));
}

static int http_add_header_internal(TALLOC_CTX *mem_ctx,
		struct http_header **headers, const char *key, const char *value)
{
	struct http_header *tail = NULL;
	struct http_header *header = NULL;

	header = talloc(mem_ctx, struct http_header);
	header->key = talloc_strdup(mem_ctx, key);
	header->value = talloc_strdup(mem_ctx, value);

	DEBUG(9, ("%s: Adding HTTP header: key '%s', value '%s'\n",
			__func__, header->key, header->value));
	DLIST_ADD_END(*headers, header, NULL);

	tail = DLIST_TAIL(*headers);
	if (tail != header) {
		DEBUG(0, ("%s: Error adding header\n", __func__));
		return -1;
	}

	return 0;
}

static int http_header_is_valid_value(const char *value)
{
	const char *p = value;

	while ((p = strpbrk(p, "\r\n")) != NULL) {
		/* we really expect only one new line */
		p += strspn(p, "\r\n");
		/* we expect a space or tab for continuation */
		if (*p != ' ' && *p != '\t')
			return (0);
	}
	return (1);
}

#if 0
const char *http_request_get_host(struct http_request *req)
{
	const char *host = NULL;

	if (req->host_cache)
		return req->host_cache;

	if (req->uri_elems)
		host = http_uri_get_host(req->uri_elems);

	if (!host && req->response_headers) {
		const char *p;
		size_t len;

		host = http_find_header(req->input_headers, "Host");
		/* The Host: header may include a port. Remove it here
		   to be consistent with uri_elems case above. */
		if (host) {
			p = host + strlen(host) - 1;
			while (p > host && EVUTIL_ISDIGIT_(*p))
				--p;
			if (p > host && *p == ':') {
				len = p - host;
				req->host_cache = mm_malloc(len + 1);
				if (!req->host_cache) {
					event_warn("%s: malloc", __func__);
					return NULL;
				}
				memcpy(req->host_cache, host, len);
				req->host_cache[len] = '\0';
				host = req->host_cache;
			}
		}
	}

	return host;
}
#endif

static NTSTATUS http_push_request(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, struct http_request *req)
{
	NTSTATUS status;

	data_blob_clear(blob);
	status = http_make_header(mem_ctx, blob, req);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("%s: Error pushing request to blob\n", __func__));
		return status;
	}
	return NT_STATUS_OK;
}
