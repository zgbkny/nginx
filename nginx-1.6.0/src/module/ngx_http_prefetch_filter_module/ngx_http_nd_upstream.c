#include "ngx_http_nd_upstream.h"
#include "ngx_http_prefetch_tcp_pool.h"

#define ND_UPSTREAM_POOL_SIZE (1024 * 12)
#define ND_UPSTREAM_BUFFER_SIZE (1024 * 4)

void
ngx_http_nd_upstream_dummy_handler(ngx_http_nd_upstream_t *u);
void 
ngx_http_nd_upstream_wev_handler(ngx_http_nd_upstream_t *u);

void 
ngx_http_nd_upstream_rev_handler(ngx_http_nd_upstream_t *u);

static ngx_int_t
ngx_http_nd_upstream_push_response(ngx_http_nd_upstream_t *u);

static void
ngx_http_nd_upstream_read_from_downstream(ngx_http_nd_upstream_t *u);

static void
ngx_http_nd_upstream_write_to_downstream(ngx_http_nd_upstream_t *u);

static void 
ngx_http_nd_upstream_event_handler(ngx_event_t *ev)
{
	ngx_http_nd_upstream_t 		*nd_u;
	ngx_connection_t			*c;
	ngx_log_debug(NGX_LOG_DEBUG_EVENT, ev->log, 0, "ngx_http_nd_upstream_event_handler");	
	c = ev->data;
	nd_u = c->data;

	if (ev->write) {
		nd_u->write_event_handler(nd_u);
	} else {
		nd_u->read_event_handler(nd_u);
	}
}

static void 
ngx_http_nd_downstream_event_handler(ngx_event_t *ev)
{
	ngx_http_nd_upstream_t 		*nd_u;
	ngx_connection_t			*c;
	ngx_log_debug(NGX_LOG_DEBUG_EVENT, ev->log, 0, "ngx_http_nd_upstream_event_handler");	
	c = ev->data;
	nd_u = c->data;

	if (ev->write) {
		nd_u->write_downstream_event_handler(nd_u);
	} else {
		nd_u->read_downstream_event_handler(nd_u);
	}
}

static ngx_int_t
ngx_http_nd_upstream_send_request(ngx_http_nd_upstream_t *u)
{
	ssize_t			 	 n;
	ngx_connection_t	*c;
	ngx_buf_t			*buffer;


	if (u->request_bufs) {
		buffer = u->request_bufs->buf;
	} else {
		return NGX_OK;
	}	

	c = u->peer.connection;
	if (buffer->last <= buffer->pos) return NGX_OK;

	ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_htto_nd_upstream_send_request check");
	n = ngx_unix_send(c, buffer->pos, buffer->last - buffer->pos);
	if (n == -1) {
		return NGX_ERROR;
	}	

	
	ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_htto_nd_upstream_send_request check 2");
	if (n < buffer->last - buffer->pos) {
		buffer->pos += n;
		return NGX_AGAIN; 	
	}
	
	ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_htto_nd_upstream_send_request:%d", n);
	return NGX_OK;
} 

static void
ngx_http_nd_upstream_read_from_downstream(ngx_http_nd_upstream_t *u)
{
	ngx_connection_t 	*c;

	c = u->conn;
	if (c->read->timedout) {
		ngx_http_nd_upstream_finalize(u, NGX_ERROR);
		return;
	}

	return;
}

static void
ngx_http_nd_upstream_write_to_downstream(ngx_http_nd_upstream_t *u)
{
	ssize_t			 	 n;
	ngx_connection_t	*c;
	ngx_buf_t			*buffer;
	ngx_chain_t 		*cl;
	ngx_int_t 	 		 event;

	c = u->conn;

	if (c->write->timedout) {
		ngx_http_nd_upstream_finalize(u, NGX_ERROR);
		return;
	}

	cl = u->push_request;

	while (cl) {
		buffer = cl->buf;

		n = ngx_unix_send(c, buffer->pos, buffer->last - buffer->pos);
		if (n == -1 || n == 0) {
			cl = NULL;
			break;
		}	

		
		if (n < buffer->last - buffer->pos) {
			buffer->pos += n;
			break; 	
		} else if (n == buffer->last - buffer->pos) {
			cl = cl->next;
		} else {
			cl = NULL;
		}
	}
	if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
		// kqueue

		event = NGX_CLEAR_EVENT;
	} else {
		// select poll 
		event = NGX_LEVEL_EVENT;
	}
	u->push_request = cl;
	if (cl == NULL) {
		// here we already send all data to client, we can cycle conn
		if (ngx_http_prefetch_put_tcp_conn(u->conn->fd, u->log) == NGX_OK) {
     
            if (u->conn->read->timer_set) {
                ngx_del_timer(u->peer.connection->read);
            }

            if (u->conn->write->timer_set) {
                ngx_del_timer(u->peer.connection->write);
            }

            if (ngx_del_conn) {
                ngx_del_conn(u->conn, NGX_DISABLE_EVENT);
            } else {
                if (u->conn->read->active || u->conn->read->disabled) {
                    ngx_del_event(u->conn->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
                }
                

                if (u->conn->write->active || u->conn->write->disabled) {
                    ngx_del_event(u->conn->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
                }
            }
            u->conn->fd = -1;
            ngx_reusable_connection(u->peer.connection, 0);
            ngx_free_connection(u->peer.connection);
            u->conn = NULL;
        } 
		ngx_http_nd_upstream_finalize(u, NGX_OK);
	} else {
		u->write_downstream_event_handler = ngx_http_nd_upstream_write_to_downstream;
		if (ngx_add_event(c->write, NGX_READ_EVENT, event) != NGX_OK) {
			return;
		}
		ngx_add_timer(c->write, u->timeout);
	}

	return;
}

static ngx_int_t
ngx_http_nd_upstream_push_response(ngx_http_nd_upstream_t *u)
{
	ngx_chain_t 			*cl;
	u_char 					 temp[20];
	ngx_socket_t 			 s;
	ngx_connection_t 		*c;
	ngx_buf_t 				*buffer;
	ngx_int_t 				 event;


	cl = u->request_bufs;
	cl->next = NULL;
	// reset request 
	cl->buf->pos = cl->buf->start;
	cl->buf->last -= 2;
	buffer = cl->buf;
	// add response
	ngx_memcpy(cl->buf->last, "Content-Length: ", 16);
	buffer->last += 16;
	ngx_memzero(temp, 20);
	ngx_snprintf(temp, 20, "%z", u->response_lens);
	ngx_memcpy(cl->buf->last, temp, strlen((const char *)temp));
	buffer->last += strlen((const char *)temp);
	ngx_memcpy(cl->buf->last, "\r\n", 2);
	buffer->last += 2;

	// construct push request
	cl->next = u->response_bufs;
	u->push_request = cl;

	// now we can send push request to client
	s = ngx_http_prefetch_get_tcp_conn(u->log);
	if (s == (ngx_socket_t) -1) {
		// attemp to syn one tcp conn
		return NGX_ERROR;
	}
	// now, we need to get conn 
	c = ngx_get_connection(s, u->log);
	if (c == NULL) {
		return NGX_ERROR;
	} else {
		c->write->ready = 1;
		c->read->ready = 1;
	}
	u->conn = c;
	if (ngx_add_conn) {
		if (ngx_add_conn(c) == NGX_ERROR) {
			return NGX_ERROR;
		}
	} else {
		return NGX_ERROR;
	}

	if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
		// kqueue

		event = NGX_CLEAR_EVENT;
	} else {
		// select poll 
		event = NGX_LEVEL_EVENT;
	}

	// here we already got one conn and we need to init it
	c->read->handler = ngx_http_nd_downstream_event_handler;
	c->write->handler = ngx_http_nd_downstream_event_handler;
	u->read_downstream_event_handler = ngx_http_nd_upstream_read_from_downstream;
	u->write_downstream_event_handler = ngx_http_nd_upstream_write_to_downstream;

	if (!c->write->ready) {
		if (ngx_add_event(c->write, NGX_READ_EVENT, event) != NGX_OK) {
			return NGX_ERROR;
		}
		ngx_add_timer(c->write, u->timeout);
	} else {
		ngx_http_nd_upstream_write_to_downstream(u);
	}

	return NGX_OK;
}

void
ngx_http_nd_upstream_dummy_handler(ngx_http_nd_upstream_t *u)
{
	return;
}

void 
ngx_http_nd_upstream_wev_handler(ngx_http_nd_upstream_t *u)
{
	ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_http_nd_upstream_wev_handler");
	ngx_connection_t	*c;
	ngx_int_t		 rc;	
	c = u->peer.connection;

	if (c->write->timedout) {
		ngx_http_nd_upstream_finalize(u, NGX_ERROR);
		return;
	}

	rc = ngx_http_nd_upstream_send_request(u);
	ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_http_nd_upstream_wev_handler:%d", rc);
	
	if (rc == NGX_ERROR) {
		ngx_http_nd_upstream_finalize(u, NGX_ERROR);
		return;
	}
	if (c->write->timer_set) {
		ngx_del_timer(c->write);
	}

	if (rc == NGX_AGAIN) {
		ngx_add_timer(c->write, u->timeout);
		if (ngx_handle_write_event(c->write, u->send_lowat) != NGX_OK) {
			ngx_http_nd_upstream_finalize(u, NGX_ERROR);
			return;
		}
		return;
	}

	// rc == NGX_OK

	ngx_add_timer(c->read, u->timeout);
	if (c->read->ready) {
		ngx_http_nd_upstream_rev_handler(u);
		return;
	} else {
	
		ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_http_nd_upstream_wev_handler set read");
		if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
			ngx_http_nd_upstream_finalize(u, NGX_ERROR);
			return;
		}
	}

	ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_http_nd_upstream_wev_handler check");
	// clear write callback
	u->write_event_handler = ngx_http_nd_upstream_dummy_handler;
	if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
		ngx_http_nd_upstream_finalize(u, NGX_ERROR);
		return;
	}

}

void 
ngx_http_nd_upstream_rev_handler(ngx_http_nd_upstream_t *u)
{
	ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_http_nd_upstream_rev_handler");
	ngx_connection_t 			*c;
	ssize_t			 			 n;
	ngx_chain_t					*cl;
	ngx_buf_t					*buffer;

	c = u->peer.connection;
	if (c->read->timedout) {
		ngx_http_nd_upstream_finalize(u, NGX_ERROR);
		return;
	}

	buffer = ngx_create_temp_buf(u->pool, ND_UPSTREAM_BUFFER_SIZE);
	if (buffer == NULL) {
		ngx_http_nd_upstream_finalize(u, NGX_ERROR);
		return;
	}
	cl = ngx_alloc_chain_link(u->pool);
	if (cl == NULL) {
		ngx_http_nd_upstream_finalize(u, NGX_ERROR);
		return;
	}
	

	for ( ; ; ) {
		

		n = ngx_unix_recv(c, buffer->last, buffer->end - buffer->last);
		ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_http_nd_upstream_rev_handler:%d", n);
		if (n == NGX_AGAIN) {
			if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
				ngx_http_nd_upstream_finalize(u, NGX_ERROR);
				return;
			}
			return;
		}			
		if (n == 0) {
			// here we start to push response to client
			if (ngx_http_nd_upstream_push_response(u) != NGX_OK) {
				ngx_http_nd_upstream_finalize(u, NGX_ERROR);
			}
			return;
		}
		if (n == NGX_ERROR) {
			ngx_http_nd_upstream_finalize(u, NGX_OK);
			return;
		}
		buffer->last += n;
		u->response_lens += n;
		ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_http_nd_upstream_rev_handler:%s", u->buffer.pos);
	}

	cl->buf = buffer;
	cl->next = NULL;
	if (u->last_response_bufs) {
		*u->last_response_bufs = cl; 
	} else {
		u->response_bufs = cl;
	}
	u->last_response_bufs = &cl->next;
}


void 
ngx_http_nd_upstream_finalize(ngx_http_nd_upstream_t *u, ngx_int_t rc)
{

	ngx_log_debug(NGX_LOG_DEBUG_EVENT, u->log, 0, "ngx_http_nd_upstream_finalize rc:%d", rc);
	if (u->peer.connection) {
		if (u->peer.connection->pool) {
			ngx_destroy_pool(u->peer.connection->pool);
		}		
		ngx_close_connection(u->peer.connection);
	} 	
	u->peer.connection = NULL;
	if (u->conn) {

		if (u->conn->pool) {
			ngx_destroy_pool(u->conn->pool);
		}
		// cycle fd 
		ngx_close_connection(u->conn);
	}
	u->conn = NULL;


	if (u->pool) {
		ngx_destroy_pool(u->pool);
	}
	
}

ngx_http_nd_upstream_t *
ngx_http_nd_upstream_create(ngx_http_request_t *r)
{
	ngx_pool_t			*pool;
	ngx_http_nd_upstream_t 		*u;

	pool = ngx_create_pool(ND_UPSTREAM_POOL_SIZE, r->connection->log);
	if (pool == NULL) {
		return NULL;
	}
	u = ngx_pcalloc(pool, sizeof(ngx_http_nd_upstream_t));
	if (u == NULL) {
		return NULL;
	}
	u->log = r->connection->log;	
	u->pool = pool;
	
	u->buffer.start = ngx_palloc(u->pool, ND_UPSTREAM_BUFFER_SIZE);
	if (u->buffer.start == NULL) {
		ngx_http_nd_upstream_finalize(u, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return NULL;
	}	
	u->buffer.pos = u->buffer.start;
	u->buffer.last = u->buffer.start;
	u->buffer.end = u->buffer.start + ND_UPSTREAM_BUFFER_SIZE;
	u->buffer.temporary = 1;

	u->buffer.tag = NULL;
	u->request_bufs = NULL;

	u->timeout = 60000; 

	u->request_bufs = NULL;
	u->response_bufs = NULL;
	u->last_response_bufs = NULL;
	u->response_lens = 0;
	u->push_request = NULL;
	u->upstream_tcp_nodelay = NGX_TCP_NODELAY_UNSET;
	u->downstream_tcp_nodelay = NGX_TCP_NODELAY_UNSET;

	return u;
}

ngx_int_t
ngx_http_nd_upstream_init(ngx_http_nd_upstream_t *u)
{
	int				 	 	 rc;
	ngx_err_t			 	 err;
	ngx_connection_t 		*c;
	ngx_socket_t			 s;
	ngx_event_t				*rev, *wev;
	ngx_int_t			 	 event;
	ngx_uint_t			  	 level;

	s = ngx_socket(u->sockaddr->sa_family, SOCK_STREAM, 0);

	ngx_log_debug1(NGX_LOG_DEBUG_EVENT, u->log, 0, "socket %d", s);
	if (s == (ngx_socket_t) -1) {
		return NGX_ERROR;
	}	

	c = ngx_get_connection(s, u->log);
	if (c == NULL) {
		return NGX_ERROR;
	}

	if (ngx_nonblocking(s) == -1) {
		ngx_log_error(NGX_LOG_ALERT, u->log, ngx_socket_errno, ngx_blocking_n " failed");
		goto failed;
	}

	rev = c->read;
	wev = c->write;
	rev->log = u->log;
	wev->log = u->log;

	if (ngx_add_conn) {
		if (ngx_add_conn(c) == NGX_ERROR) {
			goto failed;
		}
	}

	rc = connect(s, u->sockaddr, u->socklen);
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

			ngx_log_error(level, c->log, err, "connect() to failed");
			ngx_close_connection(c);
			u->peer.connection = NULL;
			return NGX_DECLINED;
		}	
	}

	u->peer.connection = c;

	// add callback here
	c->write->handler = ngx_http_nd_upstream_event_handler;
	c->read->handler = ngx_http_nd_upstream_event_handler;
	u->write_event_handler = ngx_http_nd_upstream_wev_handler;
	u->read_event_handler = ngx_http_nd_upstream_rev_handler;
	c->data = u;
		


	if (ngx_add_conn) {
		if (rc == -1) {
			return NGX_AGAIN;
		}
		wev->ready = 1;
	}
	if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
		// kqueue

		event = NGX_CLEAR_EVENT;
	} else {
		// select poll 
		event = NGX_LEVEL_EVENT;
	}

	if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
		goto failed;
	}
	if (rc == -1) {
		ngx_add_timer(c->write, u->timeout);

		// NGX_EINPROGRESS
		if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
			goto failed;
		}
		return NGX_AGAIN;
	}

	wev->ready = 1;

	ngx_http_nd_upstream_wev_handler(u);
		
	return NGX_OK;

failed:
	ngx_close_connection(c);
	u->peer.connection = NULL;
	ngx_http_nd_upstream_finalize(u, NGX_ERROR);
	return NGX_ERROR;
}
