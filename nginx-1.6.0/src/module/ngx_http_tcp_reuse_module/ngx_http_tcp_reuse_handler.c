#ifndef DDEBUG
#define DDEBUG
#endif

#include "ngx_http_tcp_reuse_module.h"
#include "ngx_http_tcp_reuse_handler.h"
#include "ngx_http_tcp_reuse_upstream.h"

#define KEEPALIVE "keep-alive"

static ngx_int_t ngx_http_tcp_reuse_create_request(ngx_http_request_t *r);

static void ngx_http_tcp_reuse_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t ngx_http_tcp_reuse_process_header(ngx_http_request_t *r);
static ngx_int_t tcp_reuse_upstream_process_header(ngx_http_request_t *r);


ngx_int_t ngx_http_tcp_reuse_handler(ngx_http_request_t *r) 
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_tcp_reuse_handler fd:%d", r->connection->fd);
    
    ngx_int_t                        rc;
    ngx_http_tcp_reuse_ctx_t        *myctx;
    ngx_http_tcp_reuse_conf_t       *mycf;
/*    ngx_buf_t                       *b;
    ngx_chain_t                      out[2];
    char                             data[100];
*/
    // open keepalive
    r->keepalive = 0;


    // get http ctx's ngx_http_tcp_reuse_ctx_t
    myctx = ngx_http_get_module_ctx(r, ngx_http_tcp_reuse_module);
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

    mycf = (ngx_http_tcp_reuse_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_tcp_reuse_module);
    ngx_http_upstream_t *u = r->upstream;
    u->conf = &mycf->upstream;
    u->buffering = mycf->upstream.buffering;

    u->resolved = (ngx_http_upstream_resolved_t *)ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_palloc resolved error, %s", strerror(errno));
        return NGX_ERROR;
    }

    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char *)mycf->backend_server.data);
    if (pHost == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }

    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)8000);
    char *pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_tcp_reuse_handler. %s", pDmsIP);
    backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backendServer.data = (u_char *)pDmsIP;
    myctx->backendServer.len = strlen(pDmsIP);

    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;

    u->create_request = ngx_http_tcp_reuse_create_request;
    u->process_header = ngx_http_tcp_reuse_process_header;
    u->finalize_request = ngx_http_tcp_reuse_finalize_request;

    rc = ngx_http_read_client_request_body(r, ngx_http_tcp_reuse_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    //r->main->count++;

    //ngx_http_tcp_reuse_upstream_init(r);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_tcp_reuse_normal r->main :%d", r->main->count);
    
    //must be NGX_DONE
    return NGX_DONE;
	
}


static ngx_int_t ngx_http_tcp_reuse_create_request(ngx_http_request_t *r)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_tcp_reuse_create_request");

    ngx_str_t                        method;
    size_t                           len = 0;
    ngx_uint_t                       i = 0;
    ngx_list_part_t                 *part;
    ngx_table_elt_t                 *header;
    ngx_buf_t                       *b;
    ngx_chain_t                     *cl, *body;//, *body;
    ngx_http_upstream_t             *u;
    //ngx_http_server_guard_conf_t    *sgcf;
    //ngx_http_server_guard_ctx_t     *ctx;  
    
    u = r->upstream;

    //sgcf = ngx_http_get_module_loc_conf(r, ngx_http_server_guard_module);

   // if (u->method.len) {
   //     method = u->method;
   //     method.len++;
   // } else {
        method = r->method_name;
        method.len++;
   // }
    

    // cal request len

    len += r->uri.len + 1 + r->http_protocol.len + 2;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request:%s", r->request_line.data);


    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        
        if (!ngx_strcmp(header[i].key.data, "Connection")) {
            header[i].value.data = (u_char *)KEEPALIVE;
            header[i].value.len = 10;
        }
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "key:%s, value:%s", header[i].key.data, header[i].value.data);
        
        len += header[i].key.len + sizeof(": ")
             + header[i].value.len + sizeof(CRLF);
    }
    len += sizeof(CRLF);
    //len += r->headers_in.content_length_n;

    b = ngx_create_temp_buf(r->pool, len);
    
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    b->last = ngx_copy(b->last, r->method_name.data, r->method_name.len);
    *b->last++ = ' ';


    b->last = ngx_copy(b->last, r->uri.data, r->uri.len);
    *b->last++ = ' ';

    b->last = ngx_copy(b->last, r->http_protocol.data, r->http_protocol.len);

    *b->last++ = CR; *b->last++ = LF;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';
        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    *b->last++ = CR; *b->last++ = LF;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request:%s", b->start);

    
    body = u->request_bufs;
    u->request_bufs = cl;
    while (body) {

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "body:%s", body->buf->start);
        b = ngx_alloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));
        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->buf = b;
        body = body->next;
    }

    cl->next = NULL;
    b->flush = 1;

    u->request_sent = 0;
    u->header_sent = 0;

    r->header_hash = 1;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_tcp_reuse_create_request over");
    return NGX_OK;
}


static void ngx_http_tcp_reuse_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_tcp_reuse_finalize_request");
}

static ngx_int_t ngx_http_tcp_reuse_process_header(ngx_http_request_t *r)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_tcp_reuse_process_header");
    size_t               len;
    ngx_int_t            rc;
    ngx_http_upstream_t *u;

    ngx_http_tcp_reuse_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_tcp_reuse_module);

    if (ctx == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uptest_process_status_line get ctx error");
        return NGX_ERROR;
    }

    u = r->upstream;
    ngx_memzero(&ctx->status, sizeof(ngx_http_tcp_reuse_ctx_t));
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    
    
    if (rc == NGX_AGAIN) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_parse_status_line again. %d", rc);
        return rc;
    }
    if (rc == NGX_ERROR) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");
        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        return NGX_OK;
    }

    if (u->state) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;
    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);

    if (u->headers_in.status_line.data == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uptest_process_status_line error");
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    u->process_header = tcp_reuse_upstream_process_header;

    return tcp_reuse_upstream_process_header(r);
}

static ngx_int_t tcp_reuse_upstream_process_header(ngx_http_request_t *r)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "tcp_reuse_upstream_process_header");
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;
//    ngx_uint_t           i = 0;
//   ngx_list_part_t     *part;
//   ngx_table_elt_t     *header;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    
    for ( ; ; ) {
        
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        
        if (rc == NGX_OK) {
            h = ngx_list_push(&r->upstream->headers_in.headers);

            if (h == NULL) {
                return NGX_ERROR;
            }
            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uu->headers_in.status_n:%d", r->upstream->headers_in.status_n);
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            } 

            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            // add reuseable
            ngx_http_upstream_t *u = r->upstream;
            ngx_connection_t *c = u->peer.connection;
            c->reusable = 0;
            // end reuseable

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}



