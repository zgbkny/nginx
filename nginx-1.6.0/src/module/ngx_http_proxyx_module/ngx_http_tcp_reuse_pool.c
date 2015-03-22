#include "ngx_http_tcp_reuse_pool.h"

#define ngx_tcp_reuse_pool_size 40960000
#define ngx_tcp_reuse_conns_init_size 10000
#define INIT_CONNECTIONS 1000

static ngx_addr_t       *conn_pool_addr; 

static ngx_pool_t 		*ngx_reuse_pool;

static ngx_array_t 		 conns;

static ngx_queue_t       empty_conns;

static ngx_queue_t       active_conns;


static void ngx_tcp_reuse_read_handler(ngx_event_t *ev);

static void ngx_tcp_reuse_write_handler(ngx_event_t *ev);

static size_t            count;
static size_t            temp_count;

//static ngx_msec_t 		 check_timeout = 3000; // ms
static ngx_event_t 		 check_ev;
static ngx_connection_t  dummy; 

void
ngx_http_tcp_reuse_pool_event_handler(ngx_event_t *ev)
{
    ngx_err_t            err = 0;
    socklen_t            len = sizeof(ngx_err_t);


    temp_count--;

    ngx_connection_t            *c;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_tcp_reuse_pool_event_handler");
    c = ev->data;

    if (ev->timedout) {
        ngx_close_connection(c);
        return;
    }

    if (ev == c->write) {

        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len);
        // add conn to pool
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_tcp_reuse_pool_event_handler add %d", err);
        if (err) {
            ngx_close_connection(c);
        } else {
             
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }
            if (c->write->timer_set) {
                ngx_del_timer(c->write);
            }

            if (ngx_tcp_reuse_put_active_conn(c, ngx_cycle->log) != NGX_OK) {
                close(c->fd);
                c->fd = -1;
                ngx_reusable_connection(c, 0);
                ngx_free_connection(c);
                c = NULL;
            }
            
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
    socklen_t                socklen = conn_pool_addr->socklen;
    struct sockaddr         *sockaddr = conn_pool_addr->sockaddr;


   /*
    // set address
    static struct sockaddr_in sock_addr;
    struct hostent *p_host = gethostbyname((char *)"192.168.0.200");
    if (p_host == NULL) {
        return NGX_ERROR;
    }
    char *ip = inet_ntoa(*(struct in_addr*) (p_host->h_addr_list[0]));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons((in_port_t)80);
    sock_addr.sin_addr.s_addr = inet_addr(ip);
    sockaddr = (struct sockaddr *)&sock_addr;
    socklen = sizeof(struct sockaddr_in); 
*/

    s = ngx_socket(sockaddr->sa_family, SOCK_STREAM, 0);

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0, "socket %d, errno:%d", s, errno);
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
    c->write->handler = ngx_http_tcp_reuse_pool_event_handler;
    c->read->handler = ngx_http_tcp_reuse_pool_event_handler;
    c->data = NULL;

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        // kqueue
        event = NGX_CLEAR_EVENT;
    } else {
        // select poll 
        event = NGX_LEVEL_EVENT;
    }
    temp_count++;
    if (rc == -1) {
        ngx_add_timer(c->write, 60000);

        // NGX_EINPROGRESS
        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            goto failed;
        }
        return NGX_OK;
    }

    wev->ready = 1;
    ngx_http_tcp_reuse_pool_event_handler(wev);
        
    return NGX_OK;

failed:
    temp_count--;
    ngx_close_connection(c);
    return NGX_ERROR;
}

static void ngx_tcp_pool_delay_timeout_handler(ngx_event_t *ev)   
{  
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_tcp_pool_delay_timeout_handler count:%d, temp_count:%d, all_count:%d", count, temp_count, count + temp_count);

    int diff = 0, i = 0;

    if (count + temp_count < INIT_CONNECTIONS) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "get tcp pool conn count:%d", count);
        diff = INIT_CONNECTIONS - count - temp_count;
        for (i = 0; i < diff; i++) {
            ngx_tcp_reuse_init_conn(ev->log);
        }
    }

    ngx_add_timer(ev, 1000);
}  

int ngx_tcp_reuse_pool_init(ngx_addr_t *addr, ngx_log_t *log)
{
	ngx_int_t    i;
    ngx_reuse_pool = ngx_create_pool(ngx_tcp_reuse_pool_size, log);
 
    conn_pool_addr = addr;

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
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_tcp_reuse_pool_init i:%d", i);
        ngx_tcp_reuse_init_conn(log);
    }

    dummy.fd = (ngx_socket_t) -1;   
  
    //ngx_memzero(&delay_ev, sizeof(ngx_event_t));  
  
    check_ev.handler = ngx_tcp_pool_delay_timeout_handler;  
    check_ev.log = ngx_cycle->log;  
    check_ev.data = &dummy;  

  	if (!check_ev.timer_set) {
    	ngx_add_timer(&check_ev, 1000);
    } 
	return NGX_OK;
}


ngx_socket_t ngx_tcp_reuse_get_active_conn(ngx_log_t *log)
{

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_tcp_reuse_get_active_conn");
	ngx_socket_t fd = -1;
	ngx_err_t    err;
	ngx_int_t    i, rc;
    ngx_int_t    diff;
	u_char test[2];
	while (!ngx_queue_empty(&active_conns)) {
		ngx_queue_t *head_conn = ngx_queue_head(&active_conns);
		ngx_tcp_reuse_conn_t *active_conn = ngx_queue_data(head_conn, ngx_tcp_reuse_conn_t, q_elt);
		fd = active_conn->fd;
		if (active_conn->c->read->timer_set) {
			ngx_del_timer(active_conn->c->read);
		}
		if (active_conn->c->write->timer_set) {
			ngx_del_timer(active_conn->c->write);
		}
		
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_tcp_reuse_get_active_conn check %d,fd:%d, %d", active_conn->c, fd, active_conn->c->log);

        if (ngx_del_conn) {
            // del it 
            ngx_del_conn(active_conn->c, NGX_DISABLE_EVENT);
        } else {
            if (active_conn->c->read->active) {
                ngx_del_event(active_conn->c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT);
            }
            if (active_conn->c->write->active) {
                ngx_del_event(active_conn->c->write, NGX_WRITE_EVENT, NGX_DISABLE_EVENT);
            }
        }
		
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_tcp_reuse_get_active_conn check 2");

		if ((rc = recv(fd, test, 1, MSG_PEEK)) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "0 : errno:%d, %s", ngx_socket_errno, strerror(errno));
			close(fd);
			fd = -1;
		} else {
            if (rc > 0) {
                close(fd);
                fd = -1;
            } else {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "!0 : errno:%d, %s", ngx_socket_errno, strerror(errno));
                err = ngx_socket_errno;
                if (err == 11) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "check");
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "check fd:%d", active_conn->c->fd);

                    active_conn->c->fd = -1;
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "check1");

                    ngx_free_connection(active_conn->c);
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "check2");

                    active_conn->c = NULL;



                    ngx_queue_remove(&active_conn->q_elt);
                    ngx_memzero(active_conn, sizeof(ngx_tcp_reuse_conn_t));
                    ngx_queue_insert_tail(&empty_conns, &active_conn->q_elt);
                    count--;
                    break;
                } else {
                    close(fd);
                    fd = -1;
                }
            }
			
		}
        ngx_close_connection(active_conn->c);
        active_conn->c = NULL;
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "fd:%d", fd);
        ngx_queue_remove(&active_conn->q_elt);
        ngx_memzero(active_conn, sizeof(ngx_tcp_reuse_conn_t));
        ngx_queue_insert_tail(&empty_conns, &active_conn->q_elt);

		count--;

    }


    if (count + temp_count < INIT_CONNECTIONS) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "get tcp pool conn count:%d", count);
        diff = INIT_CONNECTIONS - count - temp_count;
        for (i = 0; i < diff; i++) {
            ngx_tcp_reuse_init_conn(log);
        }
    }
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "get tcp pool conn:%d", fd);
	return fd;
}

static void ngx_tcp_reuse_read_handler(ngx_event_t *ev)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "ngx_tcp_reuse_read_handler");

    ngx_tcp_reuse_conn_t    *reuse_conn;
    ngx_connection_t        *c;
    c = ev->data;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "ngx_tcp_reuse_read_handler fd:%d", c->fd);


    reuse_conn = c->data;
    // close it anyway, delete it in the queue
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_tcp_reuse_read_handler //we close it anyway fd:%d", c->fd);

    // close fd;
    close(c->fd);

    // delete it from epoll
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    
    if (ngx_del_conn) {
        // del it 
        ngx_del_conn(c, NGX_DISABLE_EVENT);
    } else {
        if (c->read->active) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT);
        }
        if (c->write->active) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_DISABLE_EVENT);
        }
    }

    // delete it from queue;
    ngx_queue_remove(&reuse_conn->q_elt);
    ngx_memzero(reuse_conn, sizeof(ngx_tcp_reuse_conn_t));
    ngx_queue_insert_tail(&empty_conns, &reuse_conn->q_elt);

    ngx_free_connection(c);
    count--;
}

static void ngx_tcp_reuse_write_handler(ngx_event_t *ev)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "ngx_tcp_reuse_write_handler");

    ngx_connection_t        *c;
    ngx_tcp_reuse_conn_t    *reuse_conn;

    c = ev->data;
    reuse_conn = c->data;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_tcp_reuse_write_handler %d, fd:%d, %d", reuse_conn->c, reuse_conn->c->fd, reuse_conn->c->log);
    // dummy here 
}   

int ngx_tcp_reuse_put_active_conn(ngx_connection_t *c, ngx_log_t *log)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "put tcp pool conn (c->log) fd:%d", c->fd);
    ngx_int_t                event;
	ngx_tcp_reuse_conn_t    *new_conn = NULL;
	ngx_queue_t             *head = NULL;
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

	new_conn->fd = c->fd;
    new_conn->c = c;
    new_conn->c->data = new_conn;
    new_conn->c->read->handler = ngx_tcp_reuse_read_handler;
    new_conn->c->write->handler = ngx_tcp_reuse_write_handler;
    new_conn->c->read->log = log;
    new_conn->c->write->log = log;
    new_conn->c->log = log;
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        // kqueue
        event = NGX_CLEAR_EVENT;
    } else {
        // select poll 
        event = NGX_LEVEL_EVENT;
    }
    ngx_del_conn(new_conn->c, NGX_DISABLE_EVENT);
    if (ngx_add_event(new_conn->c->write, NGX_WRITE_EVENT, event) != NGX_OK) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "put tcp pool conn add conn write failed"); 
    }
    if (ngx_add_event(new_conn->c->read, NGX_READ_EVENT, event) != NGX_OK) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "put tcp pool conn add conn read failed"); 
    }

    ngx_add_timer(new_conn->c->read, 60000);
    
	count++;
	return NGX_OK;
}


