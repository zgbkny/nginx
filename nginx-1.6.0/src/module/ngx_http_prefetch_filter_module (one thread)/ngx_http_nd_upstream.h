/*
 * Copyright (C) William Wang
 * 
 */
#ifndef NGX_HTTP_ND_UPSTREAM_H_
#define NGX_HTTP_ND_UPSTREAM_H_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_nd_upstream_s ngx_http_nd_upstream_t;

typedef void(*ngx_http_nd_upstream_handler_pt)(ngx_http_nd_upstream_t *u);

struct ngx_http_nd_upstream_s {
	ngx_http_nd_upstream_handler_pt		read_event_handler;
	ngx_http_nd_upstream_handler_pt		write_event_handler;

	ngx_http_nd_upstream_handler_pt		read_downstream_event_handler;
	ngx_http_nd_upstream_handler_pt		write_downstream_event_handler;


	ngx_log_t						   *log;

	ngx_pool_t						   *pool;

	ngx_buf_t 							buffer;

	ngx_connection_t 				   *conn;

	ngx_peer_connection_t				peer;
	ngx_chain_t						   *request_bufs;
	ngx_chain_t						   *response_bufs;
	ngx_chain_t 					   *push_request;

	ngx_chain_t 					   *last_response_buf;
	
	int 								upstream_tcp_nodelay;
	int 								downstream_tcp_nodelay;

	size_t								response_lens;

	ngx_msec_t							timeout;
	size_t								send_lowat;
	struct sockaddr					   *sockaddr;
	socklen_t							socklen;
};


ngx_http_nd_upstream_t *
ngx_http_nd_upstream_create();

ngx_int_t 
ngx_http_nd_upstream_init(ngx_http_nd_upstream_t *u);

void 
ngx_http_nd_upstream_finalize(ngx_http_nd_upstream_t *u, ngx_int_t rc);


#endif /*NGX_HTTP_ND_UPSTREAM_H*/
