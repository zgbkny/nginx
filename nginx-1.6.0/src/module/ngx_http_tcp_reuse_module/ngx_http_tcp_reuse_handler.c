#ifndef DDEBUG
#define DDEBUG
#endif

#include "ngx_http_tcp_reuse_module.h"
#include "ngx_http_tcp_reuse_handler.h"
#include "ngx_http_tcp_reuse_processor.h"
#include "ngx_http_tcp_reuse_upstream.h"


static ngx_int_t ngx_http_tcp_reuse_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_tcp_reuse_reinit_request(ngx_http_request_t *r);
static void ngx_http_tcp_reuse_abort_request(ngx_http_request_t *r);
static void ngx_http_tcp_reuse_finalize_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_tcp_reuse_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_tcp_reuse_input_filter_init(void *data);
static ngx_int_t ngx_http_tcp_reuse_input_filter(void *data, ssize_t bytes);

ngx_int_t ngx_http_tcp_reuse_handler(ngx_http_request_t *r) 
{
	ngx_http_upstream_t			*u;
	ngx_http_tcp_reuse_conf_t	*trcf;
	
}

void ngx_http_tcp_reuse_rev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{

}

void ngx_http_tcp_reuses_wev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
	
}