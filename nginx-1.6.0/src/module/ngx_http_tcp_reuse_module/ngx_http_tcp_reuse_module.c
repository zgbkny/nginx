#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ngx_http_tcp_reuse_module.h"
#include "ngx_http_tcp_reuse_handler.h"
#include "ngx_http_tcp_reuse_upstream.h"


static char* ngx_http_tcp_reuse(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

static ngx_command_t ngx_http_tcp_reuse_cmds[] = {
	{
        ngx_string("reuse_server"), // The command name
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
        ngx_http_tcp_reuse, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
	ngx_null_command
}

static ngx_http_module_t ngx_http_tcp_reuse_module_ctx = {
	NULL,
	NULL,

	NULL,
	NULL,

	NULL,

	NULL,

	ngx_http_tcp_reuse_create_loc_conf,
	ngx_http_tcp_reuse_merge_loc_conf
}

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
}

static char* ngx_http_tcp_reuse(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_http_tcp_reuse");
    ngx_http_core_loc_conf_t* clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_tcp_reuse_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}