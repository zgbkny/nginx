#include "ngx_http_prefetch_tcp_pool.h"

#define ngx_tcp_reuse_pool_size 40960000
#define ngx_tcp_reuse_conns_init_size 10000
#define INIT_CONNECTIONS 300

static ngx_int_t
ngx_tcp_reuse_init_conn(ngx_log_t *log);

static ngx_pool_t       *ngx_reuse_pool;

static ngx_array_t       conns;

static ngx_queue_t       empty_conns;

static ngx_queue_t       active_conns;

static size_t            count;
static size_t            temp_count;

void
ngx_http_prefetch_tcp_pool_event_handler(ngx_event_t *ev)
{
    temp_count--;



    ngx_connection_t            *c;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_prefetch_tcp_pool_event_handler");
    c = ev->data;

    if (ev->timedout) {
        ngx_close_connection(c);
        return;
    }

    if (ev == c->write) {
        // add conn to pool
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_prefetch_tcp_pool_event_handler add");

        if (ngx_http_prefetch_put_tcp_conn(c->fd, c->log) == NGX_OK) {
         
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            if (c->write->timer_set) {
                ngx_del_timer(c->write);
            }

            if (ngx_del_conn) {
                ngx_del_conn(c, NGX_DISABLE_EVENT);
            } else {
                if (c->read->active || c->read->disabled) {
                    ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
                }

                if (c->write->active || c->write->disabled) {
                    ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
                }
            }
            c->fd = -1;
            ngx_reusable_connection(c, 0);
            ngx_free_connection(c);
            c = NULL;
        } else {
            ngx_close_connection(c);
        }
    } else {
        ngx_close_connection(c);
    }
}

static ngx_int_t
ngx_tcp_reuse_init_conn(ngx_log_t *log)
{
    int                      rc;
    ngx_err_t                err;
    ngx_connection_t        *c;
    ngx_socket_t             s;
    ngx_event_t             *rev, *wev;
    ngx_int_t                event;
    ngx_uint_t               level;
    socklen_t                socklen;
    struct sockaddr         *sockaddr;

    return NGX_OK;

    // set address
    static struct sockaddr_in sock_addr;
    struct hostent *p_host = gethostbyname((char *)"192.168.0.172");
    if (p_host == NULL) {
        return NGX_ERROR;
    }
    char *ip = inet_ntoa(*(struct in_addr*) (p_host->h_addr_list[0]));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons((in_port_t)8080);
    sock_addr.sin_addr.s_addr = inet_addr(ip);
    sockaddr = (struct sockaddr *)&sock_addr;
    socklen = sizeof(struct sockaddr_in); 


    s = ngx_socket(sockaddr->sa_family, SOCK_STREAM, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "socket %d", s);
    if (s == (ngx_socket_t) -1) {
        return NGX_ERROR;
    }   

    c = ngx_get_connection(s, log);

    if (c == NULL) {
        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno, ngx_blocking_n " failed");
        goto failed;
    }

    rev = c->read;
    wev = c->write;
    rev->log = log;
    wev->log = log;

    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            goto failed;
        }
    }

    rc = connect(s, sockaddr, socklen);
    if (rc == -1) {
        err = ngx_socket_errno;
        if (err != NGX_EINPROGRESS) {
            if (err == NGX_ECONNREFUSED
#if (NGX_LINUX)
                || err == NGX_EAGAIN
#endif
                || err == NGX_ECONNRESET
                || err == NGX_ENETDOWN
                || err == NGX_ENETUNREACH
                || err == NGX_EHOSTDOWN
                || err == NGX_EHOSTUNREACH) {
                level = NGX_LOG_ERR;
            } else {
                level = NGX_LOG_CRIT;
            }

            ngx_log_error(level, log, err, "connect() to failed");
            ngx_close_connection(c);
            return NGX_ERROR;
        }   
    }


    // add callback here
    c->write->handler = ngx_http_prefetch_tcp_pool_event_handler;
    c->read->handler = ngx_http_prefetch_tcp_pool_event_handler;
    c->data = NULL;

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        // kqueue

        event = NGX_CLEAR_EVENT;
    } else {
        // select poll 
        event = NGX_LEVEL_EVENT;
    }

    if (rc == -1) {
        ngx_add_timer(c->write, 60000);

        temp_count++;

        // NGX_EINPROGRESS
        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            goto failed;
        }
        return NGX_OK;
    }

    wev->ready = 1;
    ngx_http_prefetch_tcp_pool_event_handler(wev);
        
    return NGX_OK;

failed:
    ngx_close_connection(c);
    return NGX_ERROR;
}

int ngx_http_prefetch_pool_init(ngx_log_t *log)
{
    size_t               i;
    ngx_reuse_pool = ngx_create_pool(ngx_tcp_reuse_pool_size, log);
    
    if (ngx_reuse_pool == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "could not create ngx_reuse_pool");
        exit(1);
    }
    conns.elts = ngx_pcalloc(ngx_reuse_pool, ngx_tcp_reuse_conns_init_size * sizeof (ngx_tcp_reuse_conn_t));
    conns.nelts = 0;
    conns.size = sizeof (ngx_tcp_reuse_conn_t);
    conns.nalloc = ngx_tcp_reuse_conns_init_size;
    conns.pool = ngx_reuse_pool;

    ngx_queue_init(&empty_conns);
    ngx_queue_init(&active_conns);
    
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_tcp_reuse_pool_init ok");
    // init some keep-alive conn to every client
    for (i = 0; i < INIT_CONNECTIONS; i++) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_http_prefetch_pool_init i:%d", i);
        ngx_tcp_reuse_init_conn(log);
    }
    return NGX_OK;
}

ngx_socket_t ngx_http_prefetch_get_tcp_conn(ngx_log_t *log)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "http prefetch conn pool get");
    ngx_socket_t fd = -1;
    ngx_err_t    err;
    ngx_int_t    i;
    ngx_int_t    diff;

    u_char test[2];
    while (!ngx_queue_empty(&active_conns)) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "http prefetch conn pool not empty");
        ngx_queue_t *head_conn = ngx_queue_head(&active_conns);
        ngx_tcp_reuse_conn_t *active_conn = ngx_queue_data(head_conn, ngx_tcp_reuse_conn_t, q_elt);
        fd = active_conn->fd;
        if (active_conn->read.timer_set) {
            ngx_del_timer(&active_conn->read);
        }
        if (active_conn->write.timer_set) {
            ngx_del_timer(&active_conn->write);
        }
        if (active_conn->read.active) {
            ngx_del_event(&active_conn->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }
        if (active_conn->write.active) {
            ngx_del_event(&active_conn->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
        ngx_queue_remove(&active_conn->q_elt);
        ngx_memzero(active_conn, sizeof(ngx_tcp_reuse_conn_t));
        ngx_queue_insert_tail(&empty_conns, &active_conn->q_elt);

        if (recv(fd, test, 1, MSG_PEEK) == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "0 : errno:%d, %s", ngx_socket_errno, strerror(errno));
            close(fd);
            fd = -1;
        } else {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "!0 : errno:%d, %s", ngx_socket_errno, strerror(errno));
            err = ngx_socket_errno;
            if (err == 11)
                break;
            else {
                close(fd);
                fd = -1;
            }
        }
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "fd:%d", fd);

        count--;

    }

    if (count + temp_count < INIT_CONNECTIONS - 50) {
        diff = INIT_CONNECTIONS - count - temp_count;
        for (i = 0; i < diff; i++) {
            ngx_tcp_reuse_init_conn(log);
        }
    }

    return fd;
}

int ngx_http_prefetch_put_tcp_conn(ngx_socket_t fd, ngx_log_t *log)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "http prefetch conn pool put");

    ngx_tcp_reuse_conn_t *new_conn = NULL;
    ngx_queue_t *head = NULL;
    if (ngx_queue_empty(&empty_conns)) {
        new_conn = ngx_array_push(&conns);  
        if (new_conn == NULL) {
            return NGX_ERROR;
        }
    } else {
        head = ngx_queue_head(&empty_conns);
        new_conn = ngx_queue_data(head, ngx_tcp_reuse_conn_t, q_elt);
        ngx_queue_remove(&new_conn->q_elt);
    }
    ngx_queue_insert_tail(&active_conns, &new_conn->q_elt);
    new_conn->fd = fd;

    count++;

    return NGX_OK;
}