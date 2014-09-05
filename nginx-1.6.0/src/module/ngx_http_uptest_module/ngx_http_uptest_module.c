#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_http_status_t status;
    ngx_str_t backendServer;
} ngx_http_uptest_ctx_t;

typedef struct {
    ngx_http_upstream_conf_t upstream;
} ngx_http_uptest_conf_t;

static ngx_str_t ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

// To process HelloWorld command arguments
static char* ngx_http_uptest(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

// Allocate memory for HelloWorld command
static void* ngx_http_uptest_create_loc_conf(ngx_conf_t* cf);

// Copy HelloWorld argument to another place
static char* ngx_http_uptest_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

static ngx_int_t uptest_upstream_create_request(ngx_http_request_t *r);

static ngx_int_t uptest_process_status_line(ngx_http_request_t *r);

static ngx_int_t uptest_upstream_process_header(ngx_http_request_t *r);

static void uptest_upstream_finalize_request();

// Structure for the HelloWorld command
static ngx_command_t ngx_http_uptest_commands[] = {
    {
        ngx_string("uptest"), // The command name
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
        ngx_http_uptest, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

// Structure for the HelloWorld context
static ngx_http_module_t ngx_http_uptest_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_uptest_create_loc_conf,
    ngx_http_uptest_merge_loc_conf
};

// Structure for the HelloWorld module, the most important thing
ngx_module_t ngx_http_uptest_module = {
    NGX_MODULE_V1,
    &ngx_http_uptest_module_ctx,
    ngx_http_uptest_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};



static ngx_int_t ngx_http_uptest_handler(ngx_http_request_t* r) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_uptest_handler");
    // get http ctx's ngx_http_uptest_ctx_t
    ngx_http_uptest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_uptest_module);
    if (myctx == NULL) {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_uptest_ctx_t));
        if (myctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, myctx, ngx_http_uptest_module);
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

    u->create_request = uptest_upstream_create_request;
    u->process_header = uptest_process_status_line;
    u->finalize_request = uptest_upstream_finalize_request;

    r->main->count++;
    ngx_http_upstream_init(r);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_uptest_handler %s", strerror(errno));
    //must be NGX_DONE
    return NGX_DONE;
}

static ngx_int_t uptest_upstream_create_request(ngx_http_request_t *r) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uptest_upstream_create_request");
    static ngx_str_t backendQueryLine = ngx_string("GET /index.jsp HTTP/1.1\r\nHost: 192.168.0.199\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:32.0) Gecko/20100101 Firefox/32.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n");

    ngx_int_t queryLineLen = backendQueryLine.len + r->args.len;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = b->pos + queryLineLen;

    ngx_snprintf(b->pos, queryLineLen, (char *)backendQueryLine.data, &r->args);
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL) {
        return NGX_ERROR;
    }

    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;

    r->header_hash = 1;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uptest_upstream_create_request over");
    return NGX_OK;
}

static ngx_int_t uptest_process_status_line(ngx_http_request_t *r) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uptest_process_status_line");
    size_t               len;
    ngx_int_t            rc;
    ngx_http_upstream_t *u;

    ngx_http_uptest_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_uptest_module);

    if (ctx == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uptest_process_status_line get ctx error");
        return NGX_ERROR;
    }

    u = r->upstream;
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

    u->process_header = uptest_upstream_process_header;

    return uptest_upstream_process_header(r);
}

static ngx_int_t uptest_upstream_process_header(ngx_http_request_t *r) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uptest_upstream_process_header");
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

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

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void uptest_upstream_finalize_request(ngx_http_request_t *r) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uptest_upstream_finalize_request");
}

static void* ngx_http_uptest_create_loc_conf(ngx_conf_t* cf) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_http_uptest_create_loc_conf");
    ngx_http_uptest_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uptest_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->upstream.connect_timeout = 60000;
    conf->upstream.send_timeout = 60000;
    conf->upstream.read_timeout = 60000;
    conf->upstream.store_access = 0600;
    conf->upstream.buffering = 0;
    conf->upstream.bufs.num = 8;
    conf->upstream.bufs.size = ngx_pagesize;
    conf->upstream.buffer_size = ngx_pagesize;
    conf->upstream.busy_buffers_size = 2 * ngx_pagesize;
    conf->upstream.temp_file_write_size = 2 * ngx_pagesize;
    conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    return conf;
}

static char* ngx_http_uptest_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_http_uptest_merge_loc_conf");
    ngx_http_uptest_conf_t* prev = parent;
    ngx_http_uptest_conf_t* conf = child;
    
    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream, ngx_http_proxy_hide_headers, &hash) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char* ngx_http_uptest(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_http_uptest");
    ngx_http_core_loc_conf_t* clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_uptest_handler;
    //ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}
