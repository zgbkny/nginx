#include "ngx_http_tcp_reuse_pool.h"

#define ngx_tcp_reuse_pool_size 40960000
#define ngx_tcp_reuse_conns_init_size 10000

static ngx_pool_t 		*ngx_reuse_pool;

static ngx_array_t 		 conns;

static ngx_queue_t       empty_conns;

static ngx_queue_t       active_conns;

static void ngx_tcp_reuse_event_handler(ngx_event_t *ev);

static void ngx_tcp_reuse_read_handler(ngx_tcp_reuse_conn_t *reuse_conn);

static void ngx_tcp_reuse_write_handler(ngx_tcp_reuse_conn_t *reuse_conn);



int ngx_tcp_reuse_pool_init(ngx_log_t *log)
{

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
	return NGX_OK;
}


ngx_socket_t ngx_tcp_reuse_get_active_conn(ngx_log_t *log)
{
	ngx_socket_t fd = -1;
	ngx_err_t    err;
	u_char test[2];
	while (!ngx_queue_empty(&active_conns)) {
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

		if (recv(fd, test, 0, 0) == 0) {
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

	}
	return fd;
}

int ngx_tcp_reuse_put_active_conn(ngx_socket_t fd, ngx_log_t *log)
{
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
	new_conn->read_event_handler = ngx_tcp_reuse_read_handler;
	new_conn->write_event_handler = ngx_tcp_reuse_write_handler;
	new_conn->read.handler = ngx_tcp_reuse_event_handler;
	new_conn->write.handler = ngx_tcp_reuse_event_handler;
	return NGX_OK;
}

static void ngx_tcp_reuse_event_handler(ngx_event_t *ev)
{
	ngx_tcp_reuse_conn_t *reuse_conn;
	reuse_conn = ev->data;

	if (ev->write) {
		reuse_conn->write_event_handler(reuse_conn);
	} else {
		reuse_conn->read_event_handler(reuse_conn);
	}
}

static void ngx_tcp_reuse_read_handler(ngx_tcp_reuse_conn_t *reuse_conn)
{

}

static void ngx_tcp_reuse_write_handler(ngx_tcp_reuse_conn_t *reuse_conn)
{

}	