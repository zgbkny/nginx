#ifndef NGX_HTTP_TCP_REUSE_POOL_H
#define NGX_HTTP_TCP_REUSE_POOL_H

#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_tcp_reuse_conn_s 			ngx_tcp_reuse_conn_t;
typedef struct ngx_tcp_reuse_request_s	ngx_tcp_reuse_request_t;


typedef void(*ngx_tcp_reuse_pool_handler_pt) (ngx_tcp_reuse_conn_t *c);

struct ngx_tcp_reuse_conn_s{
	void               						*data;
    ngx_event_t        						 read;
    ngx_event_t        						 write;

	ngx_socket_t        					 fd;

	ngx_tcp_reuse_pool_handler_pt	         read_event_handler;
	ngx_tcp_reuse_pool_handler_pt            write_event_handler;

	ngx_queue_t		    					 q_elt;

};

struct ngx_tcp_reuse_request_s {
	void									*data;

	ngx_queue_t 							 q_elt;
};

void ngx_tcp_reuse_statistic();

int ngx_tcp_reuse_pool_init(ngx_log_t *log);

ngx_socket_t ngx_tcp_reuse_get_active_conn(ngx_log_t *log);

int ngx_tcp_reuse_put_active_conn(ngx_socket_t fd, ngx_log_t *log);

int ngx_tcp_reuse_put_delay_request(void *request, int *id);

void *ngx_tcp_reuse_get_delay_request_by_id(int id);

#endif /*NGX_HTTP_TCP_REUSE_POOL_H*/