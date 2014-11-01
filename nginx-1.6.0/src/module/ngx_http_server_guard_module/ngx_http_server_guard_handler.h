#ifndef NGX_HTTP_TCP_REUSE_HANDLER_H
#define NGX_HTTP_TCP_REUSE_HANDLER_H

#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_server_guard_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_server_guard_normal(ngx_http_request_t *r);

ngx_int_t ngx_http_tcp_reuse_process_header(ngx_http_request_t *r);

void ngx_http_tcp_reuse_finalize_request(ngx_http_request_t *r, ngx_int_t rc);



#endif /*NGX_HTTP_TCP_REUSE_HANDLER_H*/