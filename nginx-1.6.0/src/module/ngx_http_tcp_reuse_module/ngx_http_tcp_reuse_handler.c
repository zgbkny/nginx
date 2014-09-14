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
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_uptest_handler");
    // get http ctx's ngx_http_uptest_ctx_t
    ngx_http_uptest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_tcp_reuse_module);
    if (myctx == NULL) {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_tcp_reuse_ctx_t));
        if (myctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, myctx, ngx_http_tcp_reuse_module);
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    ngx_http_uptest_conf_t *mycf = (ngx_http_uptest_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_uptest_module);
    ngx_http_upstream_t *u = r->upstream;
    u->conf = &mycf->upstream;
    u->buffering = mycf->upstream.buffering;

    u->resolved = (ngx_http_upstream_resolved_t *)ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_palloc resolved error, %s", strerror(errno));
        return NGX_ERROR;
    }

    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char *)"192.168.0.199");
    if (pHost == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }

    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)80);
    char *pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_uptest_handler. %s", pDmsIP);
    backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backendServer.data = (u_char *)pDmsIP;
    myctx->backendServer.len = strlen(pDmsIP);

    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;

    u->create_request = ngx_http_tcp_reuse_create_request;
    u->process_header = ngx_http_tcp_reuse_process_header;
    u->finalize_request = ngx_http_tcp_reuse_finalize_request;

    r->main->count++;
    ngx_http_tcp_reuse_upstream_init(r);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_uptest_handler %s", strerror(errno));
    //must be NGX_DONE
    return NGX_DONE;
	
}

void ngx_http_tcp_reuse_rev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{

}

void ngx_http_tcp_reuses_wev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
	
}