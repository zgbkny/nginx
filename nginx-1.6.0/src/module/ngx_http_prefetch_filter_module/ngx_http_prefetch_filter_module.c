#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define PREFETCH_CONTENT_TYPE 	"text/"
#define PREFETCH_FLAG 		0
#define PREFETCH_NOT_FLAG 	1
#define GZIP_FLAG 		0
#define GZIP_NOT_FLAG		1


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

int 
kmp_search(char *s, int s_len, char *p, int p_len);
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
	ngx_flag_t 	flag;
	ngx_flag_t	gzip_flag;
} ngx_http_prefetch_ctx_t;

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

void 
get_next(char *p, int next[], int p_len) 
{
	next[0] = -1;
	int k = -1;
	int j = 0;
	while (j < p_len - 1) {
		if (k == -1 || p[j] == p[k]) {
			k++;
			j++;
			next[j] = k;
		} else {	
			k = next[k];
		}
	}
}

int 
kmp_search(char *s, int s_len, char *p, int p_len)
{
	if (s_len < p_len) return -1;
	int i = 0;
	int j = 0;
	int next[s_len + 1];
	ngx_memzero(next, s_len + 1);
	get_next(p, next, p_len);

	while (i < s_len && j < p_len) {
		// if j == -1 or S[i] == P[j], then i++, j++
		if (j == -1 || s[i] == p[j]) {
			i++;
			j++;
		} else {
			// if j != -1 and S[i] != P[j], then i stay, j = next[j]
			j = next[j];
		}	
	}
	if (j == p_len)
		return i - j;
	else 
		return -1;
}

static ngx_int_t
ngx_http_prefetch_header_filter(ngx_http_request_t *r)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_header_filter");
	ngx_http_upstream_t			*u;
	ngx_http_prefetch_ctx_t			*ctx;

	u = r->upstream;

	
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_header_filter going check"); 
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_header_filter before content_type:%s", 
			u->headers_in.content_type->value.data);
	ctx = ngx_http_get_module_ctx(r, ngx_http_prefetch_filter_module);
	if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_prefetch_ctx_t));
		if (ctx == NULL) {
				
			return ngx_http_next_header_filter(r);
			//return NGX_ERROR;
		}
		
		ctx->flag = PREFETCH_NOT_FLAG;
		ctx->gzip_flag = GZIP_NOT_FLAG;
		/*now we need to check if we should analysis the response*/ 
		if (u->headers_in.content_type != NULL &&
		   	u->headers_in.content_type->value.data != NULL &&
			ngx_strncmp((const char *)u->headers_in.content_type->value.data, 
					PREFETCH_CONTENT_TYPE, strlen(PREFETCH_CONTENT_TYPE)) == 0) {

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_prefetch_header_filter content_type:%s", 
					u->headers_in.content_type->value.data);
			ctx->flag = PREFETCH_FLAG;
		}		
		ngx_http_set_ctx(r, ctx, ngx_http_prefetch_filter_module);
	}

	


	return ngx_http_next_header_filter(r);
}

static void
ngx_http_prefetch_filter_url(char *buf_start, char *buf_end, ngx_log_t *log)
{
	
	ngx_str_t				src_str = ngx_string("src=");
	ngx_str_t				href_str = ngx_string("href=");
	int 					index = -1;
	int 					start = 0;	
	int 					end = 0;
	char					*buf_str;
	char					temp[1000];

	ngx_memzero(temp, 1000);
	
	buf_str = buf_start;
	start = 0;
	end  = 0;
	index = -1;
	//ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_http_prefetch_body_filter need to prefetch \n");//%s", buf_str);
	while (1) {
		buf_str = buf_str + start;
		if (buf_str > buf_end) break;
		index = kmp_search(buf_str, buf_end - buf_str, (char *)src_str.data, src_str.len);
		if (index != -1) {
			if (buf_str[index + src_str.len + 1] == '"' || buf_str[index + src_str.len]== '"') {		
				buf_str = buf_str + index + src_str.len;
				if (buf_str[0] == '"') {
					buf_str += 1;
				} 
//						ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
//							"ngx_http_prefetch_body_filter src:%s", buf_str);
				start = 0;
				end = -1;
				end = kmp_search(buf_str, buf_end - buf_str, "\"", 1); 
				
				
				if (end != -1) {

					ngx_memcpy(temp, buf_str, end);
					temp[end] = 0;			
					ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, 
							"ngx_http_prefetch_filter_url:\n%s", buf_str - 20);
					ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, 
							"ngx_http_prefetch_filter_url src:\n%s", temp);
					start = end;
				} else {
					break;
				}
			}
			break;
		} else {
			break;
		}

	}			


	buf_str = buf_start;
	start = 0;
	end  = 0;
	index = -1;
	while (1) {
		buf_str = buf_str + start;
		if (buf_str > buf_end) break;
		index = kmp_search(buf_str, buf_end - buf_str, (char *)href_str.data, href_str.len);
		if (index != -1) {
			
					
			if (buf_str[index + href_str.len + 1] == '"' || buf_str[index + href_str.len]== '"') {
						
				buf_str = buf_str + index + href_str.len;
				if (buf_str[0] == '"') {
					buf_str += 1;
				} 
//						ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
//							"ngx_http_prefetch_body_filter src:%s", buf_str);
				start = 0;
				end = -1;
				end = kmp_search(buf_str, buf_end - buf_str, "\"", 1);
				if (end != -1) {
					ngx_memcpy(temp, buf_str, end);
					
					temp[end] = 0;			
					ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, 
							"ngx_http_prefetch_filter_url:\n%s", buf_str - 20);
					ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, 
							"ngx_http_prefetch_filter_url href:\n%s", temp);
					start = end;
				} else {
					break;
				}
						
			}
			break;
		} else {
			break;
		}
	}
}

static ngx_int_t 
ngx_http_prefetch_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{

	ngx_http_prefetch_ctx_t			*ctx;
	ngx_chain_t 				*normal_chain;
	ngx_buf_t 				*buf;


	normal_chain = in;

	ctx = ngx_http_get_module_ctx(r, ngx_http_prefetch_filter_module);
	if (ctx == NULL) {
	
		return ngx_http_next_body_filter(r, in);
	//	return NGX_ERROR;
	}

	if (ctx->flag == PREFETCH_FLAG) {
		

		/*1: for some gzip or some other type content, we need to process data in buffer first
				(for example: un gzip the gzip data), then to analysis*/
		
		
		/*2: we already get normal data to analysis */
		while (normal_chain) {
			buf = normal_chain->buf;
			ngx_http_prefetch_filter_url((char *)buf->pos, (char *)buf->end, r->connection->log);
			normal_chain = normal_chain->next;
		}
	}
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
	printf("prefetch_filter_init\n");
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




