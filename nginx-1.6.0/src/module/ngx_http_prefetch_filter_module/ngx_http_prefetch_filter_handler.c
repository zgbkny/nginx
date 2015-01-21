#include "ngx_http_prefetch_filter_handler.h"
#include "ngx_http_nd_upstream.h"
#define BUFFER_SIZE (1024 * 12)

static ngx_int_t
ngx_http_analysis_url(u_char *url, size_t len, size_t *host_start, size_t *host_end, size_t *uri_start, size_t *uri_end)
{
	size_t 			index = 0;
	
	*host_start = 7;//  http://
	for (index = *host_start; index < len; index++) {
		if (url[index] == '/') break;
	}

	if (index < len - 4) {
		*host_end = index;
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
ngx_http_nd_upstream_create_request(ngx_int_t type, ngx_http_nd_upstream_t *u, u_char *url, size_t len, ngx_http_request_t *r)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, u->log, 0, "ngx_http_nd_upstream_create_request");
	ngx_chain_t 			*cl;
	ngx_buf_t 			*buffer;
//	size_t 				 len;	
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

	if (ngx_http_analysis_url(url, len, &host_start, &host_end, &uri_start, &uri_end) != NGX_OK) {
		goto error;
	}

	ngx_memcpy(buffer->last, "GET ", 4);
	buffer->last += 4;
	ngx_memcpy(buffer->last, url + uri_start, uri_end - uri_start);
	buffer->last += (uri_end - uri_start);
	ngx_memcpy(buffer->last, " HTTP/1.1\r\n", 11);
	buffer->last += 11;
	ngx_memcpy(buffer->last, "Connection: close\r\n", 19);
	buffer->last += 19;
	ngx_memcpy(buffer->last, "Host: ", 6);
	buffer->last += 6;
	ngx_memcpy(buffer->last, url + host_start, host_end - host_start);
	buffer->last += (host_end - host_start);
	ngx_memcpy(buffer->last, "\r\n", 2);
	buffer->last += 2;
	ngx_memcpy(buffer->last, "Accept: image/*\r\n", 17);
	buffer->last += 17;
	ngx_memcpy(buffer->last, "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:34.0) Gecko/20100101 Firefox/34.0\r\n", strlen("User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:34.0) Gecko/20100101 Firefox/34.0\r\n"));
	buffer->last += strlen("User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:34.0) Gecko/20100101 Firefox/34.0\r\n");
	ngx_memcpy(buffer->last, "Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n", strlen("Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n"));
	buffer->last += strlen("Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n");
	ngx_memcpy(buffer->last, "Accept-Encoding: deflate\r\n", strlen("Accept-Encoding: deflate\r\n"));
	buffer->last += strlen("Accept-Encoding: deflate\r\n");
	
	if (r->headers_in.referer) {
		ngx_memcpy(buffer->last, "Referer: ", 9);
		buffer->last += 9;

		ngx_memcpy(buffer->last, r->headers_in.referer->value.data, r->headers_in.referer->value.len);
		buffer->last += r->headers_in.referer->value.len;
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, u->log, 0, "ngx_http_nd_upstream_create_request: referer:%s", 
					r->headers_in.referer->value.data);
		ngx_memcpy(buffer->last, "\r\n", 2);
		buffer->last += 2;
	}
	ngx_memcpy(buffer->last, "\r\n", 2);
	buffer->last += 2;

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, u->log, 0, "ngx_http_nd_upstream request:%s", 
					buffer->pos);
	cl->buf = buffer;
	cl->next = NULL;
	u->request_bufs = cl;
	return NGX_OK;
error:
	return NGX_ERROR;

}

void
ngx_http_prefetch_handle_url(ngx_int_t type, u_char *url, size_t len, ngx_http_request_t *r)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_handle_url");
	ngx_http_nd_upstream_t 		*nd_u;
	ngx_int_t 			 rc;	
	
	// first we need to create a nd upstream
	nd_u = ngx_http_nd_upstream_create();
	if (nd_u == NULL) {
		return;
	}
	


	rc = ngx_http_nd_upstream_create_request(type, nd_u, url, len, r);
	if (rc != NGX_OK) {
		return;
	}	
	// set address
	static struct sockaddr_in sock_addr;
	struct hostent *p_host = gethostbyname((char *)"localhost");
	if (p_host == NULL) {
		ngx_http_nd_upstream_finalize(nd_u, NGX_ERROR);
		return;
	}
	char *ip = inet_ntoa(*(struct in_addr*) (p_host->h_addr_list[0]));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons((in_port_t)80);
	sock_addr.sin_addr.s_addr = inet_addr(ip);
	nd_u->sockaddr = (struct sockaddr *)&sock_addr;
	nd_u->socklen = sizeof(struct sockaddr_in);	
	// init nd_upstream to send request
	ngx_http_nd_upstream_init(nd_u);	

	// debug
	//ngx_http_nd_upstream_finalize(nd_u, NGX_OK);
}


