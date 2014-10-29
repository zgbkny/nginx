#ifndef NGX_HTTP_TCP_REUSE_HANDLER_H
#define NGX_HTTP_TCP_REUSE_HANDLER_H

#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_server_guard_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_server_guard_normal(ngx_http_request_t *r);

#endif /*NGX_HTTP_TCP_REUSE_HANDLER_H*/