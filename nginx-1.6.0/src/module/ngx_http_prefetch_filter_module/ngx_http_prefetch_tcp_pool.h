#ifndef NGX_HTTP_PREFETCH_TCP_POOL_H_
#define NGX_HTTP_PREFETCH_TCP_POOL_H_


#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_tcp_reuse_conn_s ngx_tcp_reuse_conn_t;

struct ngx_tcp_reuse_conn_s{
    void                                    *data;
    ngx_event_t                              read;
    ngx_event_t                              write;

    ngx_socket_t                             fd;

    ngx_queue_t                              q_elt;

};

int ngx_tcp_reuse_pool_init(ngx_log_t *log);

ngx_socket_t ngx_http_prefetch_get_tcp_conn(ngx_log_t *log);

int ngx_http_prefetch_put_tcp_conn(ngx_socket_t fd, ngx_log_t *log);

#endif /*NGX_HTTP_PREFETCH_TCP_POOL_H_*/