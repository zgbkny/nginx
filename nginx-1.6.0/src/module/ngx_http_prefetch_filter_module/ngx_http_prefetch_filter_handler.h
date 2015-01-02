/*
 *	Copyright by William Wang
 *
 */

#ifndef NGX_HTTP_PREFETCH_FILTER_HANDLER_H_
#define NGX_HTTP_PREFETCH_FILTER_HANDLER_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



#define NGX_GIF_RETURN		2
#define NGX_PNG_RETURN		3
#define NGX_JPG_RETURN 		4
#define NGX_CSS_RETURN		5
#define NGX_JS_RETURN 		6
#define NGX_FLV_RETURN		7
#define NGX_ICO_RETURN 		8
#define NGX_SWF_RETURN		9 


void
ngx_http_prefetch_handle_url(ngx_int_t type, char *url, ngx_http_request_t *r);




#endif /*NGX_HTTP_PREFETCH_FILTER_HANDLER_H_*/
