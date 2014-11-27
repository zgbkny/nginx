#ifndef NGX_HTTP_TCP_REUSE_POOL_H
#define NGX_HTTP_TCP_REUSE_POOL_H

#include <ngx_core.h>
#include <ngx_http.h>

#define KEEPALIVE "keep-alive"


#define DELAY 		1
#define PROCESSING	2
#define DONE		3
#define ERROR 		4

#define CONNECT     0
#define DISCONNECT  1

typedef struct ngx_tcp_reuse_conn_s 		 ngx_tcp_reuse_conn_t;
typedef struct ngx_tcp_reuse_request_s		 ngx_tcp_reuse_request_t;
typedef struct ngx_tcp_reuse_resp_stat_s     ngx_tcp_reuse_resp_stat_t;
typedef struct ngx_tcp_reuse_conn_stat_s 	 ngx_tcp_reuse_conn_stat_t;


typedef void(*ngx_tcp_reuse_pool_handler_pt) (ngx_tcp_reuse_conn_t *c);

typedef void(*ngx_delay_request_handler_pt) (ngx_http_request_t *r, ngx_http_request_t *second_r);

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

	ngx_log_t 								*log;
	ngx_pool_t 								*pool;
	ngx_chain_t 							*cl;
	size_t									 state;
	ngx_queue_t 							 q_elt;
};

struct ngx_tcp_reuse_resp_stat_s {
	ngx_msec_t  							 resp_time;
	ngx_queue_t 							 q_elt;

};

struct ngx_tcp_reuse_conn_stat_s {
	size_t                                   conn_state:DISCONNECT;
	ngx_queue_t 							 q_elt;

};

int check_overload();

void ngx_tcp_reuse_statistic();

int ngx_tcp_reuse_pool_init(ngx_log_t *log);

ngx_socket_t ngx_tcp_reuse_get_active_conn(ngx_log_t *log);

int ngx_tcp_reuse_put_active_conn(ngx_socket_t fd, ngx_log_t *log);

int ngx_tcp_reuse_put_delay_request(ngx_http_request_t *r, int *id);

int ngx_tcp_reuse_process_delay_request(ngx_http_request_t *r, size_t id);

size_t ngx_tcp_reuse_get_queue_time();

size_t ngx_tcp_reuse_get_request_state(size_t id);

size_t ngx_tcp_reuse_update_ttfb_stat(ngx_msec_t time);

size_t ngx_tcp_reuse_update_resp_stat(ngx_msec_t time);

size_t ngx_tcp_reuse_update_conn_stat(size_t conn_state);


#endif /*NGX_HTTP_TCP_REUSE_POOL_H*/