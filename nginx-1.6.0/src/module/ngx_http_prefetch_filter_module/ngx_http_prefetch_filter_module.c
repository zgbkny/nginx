#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;


static ngx_int_t
ngx_http_prefetch_filter_init(ngx_conf_t *cf);

static ngx_int_t
ngx_http_prefetch_header_filter(ngx_http_request_t *r);

static ngx_int_t 
ngx_http_prefetch_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static void*
ngx_http_prefetch_create_conf(ngx_conf_t *cf);

static char * 
ngx_http_prefetch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void*
ngx_http_prefetch_create_conf(ngx_conf_t *cf);

static char*
ngx_http_prefetch_merge_conf(ngx_conf_t *cf, void *parent, void *child);



typedef struct {
	char *test;
} ngx_http_prefetch_conf_t;

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


static ngx_http_module_t ngx_http_prefetch_filter_module_ctx = {
	NULL,				 						/* preconfiguration */
	ngx_http_prefetch_filter_init, 							/* postconfiguration */

	NULL, 										/* create main configuration */
	NULL, 										/* init main configuration */

	NULL, 										/* create server configuration */
	NULL, 										/* merge servre configuration */

	ngx_http_prefetch_create_conf, 							/* create location configuration */
	ngx_http_prefetch_merge_conf							/* merge location configuration */
};
ngx_module_t ngx_http_prefetch_filter_module = {
	NGX_MODULE_V1,
	&ngx_http_prefetch_filter_module_ctx,						/* module context */
	ngx_http_prefetch_filter_commands, 						/* module directives */
	NGX_HTTP_MODULE,								/* module type */
	NULL,										/* init master */
	NULL,										/* init module */
	NULL,										/* init process */
	NULL,										/* init thread */
	NULL,										/* exit thread */
	NULL,										/* exit process */
	NULL,										/* exit master */
	NGX_MODULE_V1_PADDING

};


static ngx_int_t
ngx_http_prefetch_header_filter(ngx_http_request_t *r)
{
	
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_header_filter");
	return ngx_http_next_header_filter(r);
}

static ngx_int_t 
ngx_http_prefetch_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_body_filter");
	return ngx_http_next_body_filter(r, in);
}

static char * 
ngx_http_prefetch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

	return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_prefetch_filter_init(ngx_conf_t *cf)
{
	/* insert header handler to the head of the filter handlers */
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_prefetch_header_filter;

	/* insert body handler to the head of the filter handlers */
	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_prefetch_body_filter;

	return NGX_OK;
}

static void*
ngx_http_prefetch_create_conf(ngx_conf_t *cf)
{
	ngx_http_prefetch_conf_t *conf;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_prefetch_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	return conf;
}

static char*
ngx_http_prefetch_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
//	ngx_http_prefetch_conf_t *prev = parent;
//	ngx_http_prefetch_conf_t *conf = child;

	return NGX_CONF_OK;
}




