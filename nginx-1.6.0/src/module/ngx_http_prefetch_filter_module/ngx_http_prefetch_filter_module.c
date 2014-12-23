#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_http_module_t ngx_http_prefetch_filter_module_ctx = {
	ngx_http_prefetch_add_variables, 						/* preconfiguration */
	ngx_http_prefetch_filter_init, 							/* postconfiguration */

	NULL, 										/* create main configuration */
	NULL, 										/* init main configuration */

	NULL, 										/* create server configuration */
	NULL, 										/* merge servre configuration */

	ngx_http_prefetch_create_conf, 							/* create location configuration */
	ngx_http_prefetch_merge_conf							/* merge location configuration */
}

static ngx_command_t ngx_http_prefetch_filter_commands[] = {
	{ 	ngx_string("prefetch"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_http_prefetch,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	ngx_null_command
};

ngx_module_t ngx_http_prefetch_filter_module = {
	NGX_MODULE_V1,
	&ngx_http_prefetch_filter_module_ctx,						/* module context */
	ngx_http_prefetch_filter_commands, 						/* module directives */
	ngx_HTTP_MODULE,								/* module type */
	NULL,										/* init master */
	NULL,										/* init module */
	NULL,										/* init process */
	NULL,										/* init thread */
	NULL,										/* exit thread */
	NULL,										/* exit process */
	NULL,										/* exit master */
	NGX_MODULE_V1_PADDING

}

char * ngx_http_prefetch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

	return NGX_CONF_OK;
}




