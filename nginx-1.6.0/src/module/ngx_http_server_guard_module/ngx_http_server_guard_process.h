#ifndef NGX_HTTP_SERVER_GUARD_PROCESS_H
#define NGX_HTTP_SERVER_GUARD_PROCESS_H

#define SERVER_OVERLOAD 0
#define SERVER_NOTOVERLOAD 1

#include <ngx_config.h>
#include <nginx.h>
#include <ngx_http.h>
#include <ngx_core.h>


void ngx_http_server_guard_process(ngx_http_request_t *r);
void ngx_http_server_guard_init();

#endif /*NGX_HTTP_SERVER_GUARD_PROCESS_H*/