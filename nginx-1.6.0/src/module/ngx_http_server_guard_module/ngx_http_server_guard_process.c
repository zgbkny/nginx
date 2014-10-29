#include "ngx_http_server_guard_process.h"
#include "ngx_http_tcp_reuse_pool.h"
#include "ngx_http_server_guard_handler.h"

#define dd printf

//static ngx_msec_t check_timeout = 3000; // ms

//static ngx_event_t check_event;

//static void ngx_http_server_guard_process_handler();

static void ngx_http_server_guard_process_delay(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_processing(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_done(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_error(ngx_http_request_t *r, size_t id);

int check_overload()
{
	static int i = 5;
	i++;
	if (i > 1) 
		return SERVER_OVERLOAD;
	else 
		return SERVER_NOTOVERLOAD;
}

void ngx_http_server_guard_init(ngx_log_t *log)
{
}

void ngx_http_server_guard_process(ngx_http_request_t *r)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process");
	ngx_chain_t 			*cl = r->request_body->bufs;
	ngx_buf_t 				*buf;
	//ngx_str_t				*temp;
	int						 id = -1;


	// should use a new buf to store all request body
	while (cl) {
		buf = cl->buf;
		id = ngx_atoi(buf->start, buf->last - buf->start);
		cl = cl->next;
	}
	// also need to check request content

	switch(ngx_tcp_reuse_get_request_state(id)) {
	case DELAY:
		ngx_http_server_guard_process_delay(r, id);
		break;
	case PROCESSING:
		ngx_http_server_guard_process_processing(r, id);
		break;
	case DONE:
		ngx_http_server_guard_process_done(r, id);
		break;
	default:// we need to process invalid request
		ngx_http_server_guard_process_error(r, id);
		break;
	}
}
/*
static void ngx_http_server_guard_process_handler()
{
	//ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_server_guard_process_handler");
	ngx_http_request_t *r = ngx_tcp_reuse_get_delay_request();
	if (r) {
		r->subrequest_in_memory = 1;
		ngx_http_server_guard_normal(r);
		//r = ngx_tcp_reuse_get_delay_request();
	}
}*/

// this is the handler when reqeust is not handle 
static void ngx_http_server_guard_process_delay(ngx_http_request_t *r, size_t id)
{

}

static void ngx_http_server_guard_process_processing(ngx_http_request_t *r, size_t id)
{

}

static void ngx_http_server_guard_process_done(ngx_http_request_t *r, size_t id)
{

}

static void ngx_http_server_guard_process_error(ngx_http_request_t *r, size_t id)
{

}
