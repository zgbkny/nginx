#include "ngx_http_nd_upstream.h"

#define ND_UPSTREAM_POOL_SIZE (1024 * 12)
#define ND_UPSTREAM_BUFFER_SIZE (1024 * 4)


void 
ngx_http_nd_upstream_finalize(ngx_http_nd_upstream_t *u, ngx_int_t rc)
{
	
	
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

	return u;
}

void 
ngx_http_nd_upstream_init(ngx_http_nd_upstream_t *u)
{

}
