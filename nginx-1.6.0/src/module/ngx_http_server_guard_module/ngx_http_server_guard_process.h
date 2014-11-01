#ifndef NGX_HTTP_SERVER_GUARD_PROCESS_H
#define NGX_HTTP_SERVER_GUARD_PROCESS_H

#define SERVER_OVERLOAD 0
#define SERVER_NOTOVERLOAD 1

#include <ngx_config.h>
#include <nginx.h>
#include <ngx_http.h>
#include <ngx_core.h>

int check_overload();
void ngx_http_server_guard_process(ngx_http_request_t *r);
void ngx_http_server_guard_init();

void ngx_http_server_guard_close_connection(ngx_connection_t *c);

void ngx_http_server_guard_release_connection(ngx_connection_t *c);

#endif /*NGX_HTTP_SERVER_GUARD_PROCESS_H*/