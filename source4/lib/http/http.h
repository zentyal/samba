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

#ifndef _HTTP_H_
#define _HTTP_H_

#include <limits.h>
#include <sys/uio.h>

#include <tevent.h>
#include "lib/tsocket/tsocket.h"

/* struct tevent_context; */
/* struct tstream_context; */

/* Response codes */
#define HTTP_OK				200		/**< request completed ok */
#define HTTP_NOCONTENT			204		/**< request does not have content */
#define HTTP_MOVEPERM			301		/**< the uri moved permanently */
#define HTTP_MOVETEMP			302		/**< the uri moved temporarily */
#define HTTP_NOTMODIFIED		304		/**< page was not modified from last */
#define HTTP_BADREQUEST			400		/**< invalid http request was made */
#define HTTP_NOTFOUND			404		/**< could not find content for uri */
#define HTTP_BADMETHOD			405		/**< method not allowed for this uri */
#define HTTP_ENTITYTOOLARGE		413		/**<  */
#define HTTP_EXPECTATIONFAILED		417		/**< we can't handle this expectation */
#define HTTP_INTERNAL			500		/**< internal error */
#define HTTP_NOTIMPLEMENTED		501		/**< not implemented */
#define HTTP_SERVUNAVAIL		503		/**< the server is not available */

#define HTTP_MAX_HEADER_SIZE 	UINT_MAX

enum http_cmd_type {
	HTTP_REQ_GET     = 1 << 0,
	HTTP_REQ_POST    = 1 << 1,
	HTTP_REQ_HEAD    = 1 << 2,
	HTTP_REQ_PUT     = 1 << 3,
	HTTP_REQ_DELETE  = 1 << 4,
	HTTP_REQ_OPTIONS = 1 << 5,
	HTTP_REQ_TRACE	 = 1 << 6,
	HTTP_REQ_CONNECT = 1 << 7,
	HTTP_REQ_PATCH	 = 1 << 8,
	HTTP_REQ_RPC_IN_DATA  = 1 << 9,
	HTTP_REQ_RPC_OUT_DATA = 1 << 10,
};


enum http_parser_state {
	HTTP_READING_FIRSTLINE,	/**< reading Request-Line (incoming conn) or
				 **< Status-Line (outgoing conn) */
	HTTP_READING_HEADERS,	/**< reading request/response headers */
	HTTP_READING_BODY,	/**< reading request/response body */
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


struct http_header {
	struct http_header	*next, *prev;
	const char		*key;
	const char		*value;
};


struct http_request {
	enum http_cmd_type	type;				/* HTTP command type */
	char			major;				/* HTTP version major number */
	char			minor;				/* HTTP version minor number */
	char			*uri;				/* URI after HTTP request was parsed */
	struct http_header	*headers;
	size_t			headers_size;
	unsigned int		response_code;			/* HTTP Response code */
	char			*response_code_line;		/* Readable response */
	DATA_BLOB		body;
};

struct http_send_request_state {
	struct tevent_context	*ev;
	struct tstream_context	*stream;
	struct http_request	*request;
	DATA_BLOB		buffer;
	struct iovec		iov;
	ssize_t			nwritten;
	int			sys_errno;
};

struct http_read_response_state {
	enum http_parser_state	parser_state;
	size_t			max_headers_size;
	DATA_BLOB		buffer;
	struct http_request	*response;
	int			ret;
	int			sys_errno;
};


struct tevent_req	*http_send_request_send(TALLOC_CTX *, struct tevent_context *, struct tstream_context *, 
						struct tevent_queue *, struct http_request *);
int			http_send_request_recv(struct tevent_req *, int *);
struct tevent_req	*http_read_response_send(TALLOC_CTX *, struct tevent_context *, struct tstream_context *);
int			http_read_response_recv(struct tevent_req *, TALLOC_CTX *, struct http_request **, int *);
int			http_remove_header(struct http_header **, const char *);
int			http_add_header(TALLOC_CTX *, struct http_header **, const char *, const char *);

#endif /* _HTTP_H_ */
