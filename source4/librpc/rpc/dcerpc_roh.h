/*
 * dcerpc_roh.h
 *
 *  Created on: May 7, 2013
 *      Author: zen
 */

#ifndef DCERPC_ROH_H_
#define DCERPC_ROH_H_

#define ROH_DEFAULT_TIMEOUT 2

struct tevent_queue;
struct tstream_context;

struct roh_channel
{
	struct GUID channel_cookie;

	struct tevent_queue *send_queue;
	struct tstream_context *stream;
};

enum roh_protocol_version {
	ROH_V1,
	ROH_V2,
};

enum roh_connection_state {
	ROH_OUT_CHANNEL_WAIT,
	ROH_WAIT_A3W,
	ROH_WAIT_C2,
	ROH_OPENED,
};

/**
 * protocol_version: A client node should be capable of using v1 and v2, try
 * 					 to use v2 in first place. If it fails, fall back to v1
 * connection_state:	Tracks the protocol current state
 * connection_cookie:	Identifies the virtual connection among a
 * 						client, one or more inbound proxies, one or more
 * 						outbound proxies, and a server
 * association_group_id_cookie: Used by higher layer protocols to link multiple
 * 								virtual connections (2.2.3.1)
 * default_channel_in:
 * default_channel_out:
 * non_default_channel_in:
 * non_default_channel_out:
 */
struct roh_connection {
	const char *server_name;
	struct tevent_context *ev;

	int timeout_seconds;

	enum roh_protocol_version protocol_version;
	enum roh_connection_state connection_state;

	struct GUID connection_cookie;
	struct GUID association_group_id_cookie;

	struct roh_channel *default_channel_in;
	struct roh_channel *non_default_channel_in;

	struct roh_channel *default_channel_out;
	struct roh_channel *non_default_channel_out;

	/* Client role specific fields (3.2.2.1) */
	bool proxy_use;
	uint32_t current_keep_alive_time;
	uint32_t current_keep_alive_interval;

	/* TODO Add timers 3.2.2.2 */
};


#endif /* DCERPC_ROH_H_ */
