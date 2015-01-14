#ifndef NGX_HTTP_PUSH_HANDLER_H
#define NGX_HTTP_PUSH_HANDLER_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t 
ngx_http_push_handle(ngx_http_request_t *r, ngx_int_t rc);

#endif /*NGX_HTTP_PUSH_HANDLER_H*/