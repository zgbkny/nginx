/*
 * Copyright (C) William Wang
 * 
 */
#ifndef NGX_HTTP_ND_UPSTREAM_H_
#define NGX_HTTP_ND_UPSTREAM_H_
typedef struct ngx_http_nd_upstream_s ngx_http_nd_upstream_t;

typedef void(*ngx_http_nd_upstream_handler_pt)(ngx_http_nd_upstream_t *u);

struct ngx_http_nd_upstream_s {
	ngx_http_nd_upstream_handler_pt		read_event_handler;
	ngx_http_nd_upstream_handler_pt		write_event_handler;

	ngx_peer_connection_t			peer;
};

#endif /*NGX_HTTP_ND_UPSTREAM_H*/
