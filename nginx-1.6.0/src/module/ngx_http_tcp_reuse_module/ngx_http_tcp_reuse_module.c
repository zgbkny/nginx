#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ngx_http_tcp_reuse_module.h"
#include "ngx_http_tcp_reuse_handler.h"
#include "ngx_http_tcp_reuse_upstream.h"

static ngx_command_t ngx_http_tcp_reuse_cmds[] = {
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
}