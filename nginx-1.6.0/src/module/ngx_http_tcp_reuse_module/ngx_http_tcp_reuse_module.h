#ifndef NGX_HTTP_TCP_REUSE_MODULE_H
#define NGX_HTTP_TCP_REUSE_MODULE_H


#include <ngx_config.h>
#include <nginx.h>
#include <ngx_http.h>
#include <ngx_core.h>

typedef struct {
    ngx_http_status_t status;
    ngx_str_t backendServer;
} ngx_http_tcp_reuse_ctx_t;

typedef struct {
    ngx_http_upstream_conf_t upstream;
} ngx_http_tcp_reuse_conf_t;

extern ngx_str_t ngx_http_proxy_hide_headers[];
extern ngx_module_t ngx_http_tcp_reuse_module;

#endif /*NGX_HTTP_TCP_REUSE_MODULE_H*/