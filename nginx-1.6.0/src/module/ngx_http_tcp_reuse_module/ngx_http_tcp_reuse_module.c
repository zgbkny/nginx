#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ngx_http_tcp_reuse_module.h"
#include "ngx_http_tcp_reuse_handler.h"
#include "ngx_http_tcp_reuse_upstream.h"
#include "ngx_http_tcp_reuse_pool.h"

char* ngx_http_tcp_reuse(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

// Allocate memory for HelloWorld command
void* ngx_http_tcp_reuse_create_loc_conf(ngx_conf_t* cf);

// Copy HelloWorld argument to another place
char* ngx_http_tcp_reuse_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

ngx_str_t ngx_http_proxy_hide_headers[] = {
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

static ngx_command_t ngx_http_tcp_reuse_cmds[] = {
    {
        ngx_string("reuse_server"), // The command name
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
        ngx_http_tcp_reuse, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_tcp_reuse_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    NULL,

    NULL,

    ngx_http_tcp_reuse_create_loc_conf,
    ngx_http_tcp_reuse_merge_loc_conf
};

ngx_module_t ngx_http_tcp_reuse_module = {
    NGX_MODULE_V1,
    &ngx_http_tcp_reuse_module_ctx,
    ngx_http_tcp_reuse_cmds,
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

char* ngx_http_tcp_reuse(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_http_tcp_reuse");
    ngx_http_tcp_reuse_conf_t *mycf = conf;

    /* cf->args is a ngx_array_t queue, every element in it is ngx_str_t.*/
    ngx_str_t *value = cf->args->elts; 

    if (cf->args->nelts > 1) {
        mycf->backend_server = value[1];
    }

    ngx_tcp_reuse_pool_init(cf->log);
    ngx_http_core_loc_conf_t* clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_tcp_reuse_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

void* ngx_http_tcp_reuse_create_loc_conf(ngx_conf_t* cf) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_http_uptest_create_loc_conf");
    ngx_http_tcp_reuse_conf_t* conf;

    

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcp_reuse_conf_t));
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

char* ngx_http_tcp_reuse_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_http_uptest_merge_loc_conf");
    ngx_http_tcp_reuse_conf_t* prev = parent;
    ngx_http_tcp_reuse_conf_t* conf = child;
    
    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream, ngx_http_proxy_hide_headers, &hash) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}