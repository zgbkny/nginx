#ifndef NGX_HTTP_TCP_REUSE_HANDLER_H
#define NGX_HTTP_TCP_REUSE_HANDLER_H

#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_tcp_reuse_handler(ngx_http_request_t *r);

void ngx_http_tcp_reuse_rev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);

void ngx_http_tcp_reuses_wev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);


#endif /*NGX_HTTP_TCP_REUSE_HANDLER_H*/