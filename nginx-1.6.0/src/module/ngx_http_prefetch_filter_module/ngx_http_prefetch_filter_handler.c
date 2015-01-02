#include "ngx_http_prefetch_filter_handler.h"
#include "ngx_http_nd_upstream.h"
#define BUFFER_SIZE (1024 * 4)

static ngx_int_t
ngx_http_analysis_url(char *url, size_t *host_start, size_t *host_end, size_t *uri_start, size_t *uri_end)
{
	size_t 			index = 0;
	size_t 			len = strlen(url);
	*host_start = 7;//  http://
	for (index = *host_start; index < len; index++) {
		if (url[index] == '/') break;
	}

	if (index < len - 4) {
		*host_end = index - 1;
		*uri_start = index;
		*uri_end = len;
		return NGX_OK;
	} else {
		*host_start = -1;
		return NGX_ERROR;
	}
}


/*
 * 
 *
 *
 */

static ngx_int_t
ngx_http_nd_upstream_create_request(ngx_int_t type, ngx_http_nd_upstream_t *u, char *url, ngx_http_request_t *r)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, u->log, 0, "ngx_http_nd_upstream_create_request");
	ngx_chain_t 			*cl;
	ngx_buf_t 			*buffer;
	size_t 				 len;	
	size_t 				 host_start;
	size_t				 host_end;
	size_t 				 uri_start;
	size_t 				 uri_end;

	// construct request 
	buffer = ngx_create_temp_buf(u->pool, BUFFER_SIZE);
	if (buffer == NULL) {
		return NGX_ERROR;
	}
	cl = ngx_alloc_chain_link(u->pool);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	if (ngx_http_analysis_url(url, &host_start, &host_end, &uri_start, &uri_end) != NGX_OK) {
		goto error;
	}

	ngx_memcpy(buffer->last, "GET ", 4);
	buffer->last += 4;
	ngx_memcpy(buffer->last, url + host_start, host_end - host_start);
	buffer->last += (host_end - host_start);
	ngx_memcpy(buffer->last, " HTTP/1.0\r\n", 11);
	buffer->last += 11;

	if (r->headers_in.referer)	
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, u->log, 0, "ngx_http_nd_upstream_create_request: referer:%s", 
					r->headers_in.referer->value.data);

	cl->buf = buffer;
	cl->next = NULL;
	u->request_bufs = cl;
	return NGX_OK;
error:
	return NGX_ERROR;

}

void
ngx_http_prefetch_handle_url(ngx_int_t type, char *url, ngx_http_request_t *r)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_handle_url");
	ngx_http_nd_upstream_t 		*nd_u;
	ngx_int_t 			 rc;	

	// first we need to create a nd upstream
	nd_u = ngx_http_nd_upstream_create(r);
	if (nd_u == NULL) {
		return;
	}
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_handle_url check");
	rc = ngx_http_nd_upstream_create_request(type, nd_u, url, r);
	if (rc != NGX_OK) {
		return;
	}	
	// set address
	
	// init nd_upstream to send request
	ngx_http_nd_upstream_init(nd_u);	
}


