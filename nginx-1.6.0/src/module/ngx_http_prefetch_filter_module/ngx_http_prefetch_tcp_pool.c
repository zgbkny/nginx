#include "ngx_http_prefetch_tcp_pool.h"



int ngx_tcp_reuse_pool_init(ngx_log_t *log)
{
    // init some keep-alive conn to every client
    return NGX_OK;
}

ngx_socket_t ngx_tcp_reuse_get_active_conn(ngx_log_t *log)
{
    ngx_socket_t        fd = -1;

    return fd;
}

int ngx_tcp_reuse_put_active_conn(ngx_socket_t fd, ngx_log_t *log)
{

    return NGX_OK;
}