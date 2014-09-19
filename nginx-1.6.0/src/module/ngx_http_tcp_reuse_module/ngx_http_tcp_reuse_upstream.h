#ifndef NGX_HTTP_TCP_REUSE_UPSTREAM_H
#define NGX_HTTP_TCP_REUSE_UPSTREAM_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>




void ngx_http_tcp_reuse_upstream_init(ngx_http_request_t *r);

#endif /*NGX_HTTP_TCP_REUSE_UPSTREAM_H*/