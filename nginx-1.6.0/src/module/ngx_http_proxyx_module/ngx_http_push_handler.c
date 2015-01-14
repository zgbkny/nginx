#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_push_handler.h"

ngx_int_t 
ngx_http_push_handle(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_chain_t             *cl;
    ngx_buf_t               *buffer;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle uri:%s", r->uri.data);

    if (r->request_body) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle:");

        cl  = r->request_body->bufs;
        if (cl == NULL) {
            goto next;
        }
        buffer = cl->buf;
        if (buffer == NULL) {
            goto next;
        } 

        

    } else {
        goto next;
    }

next:    
    return rc;
}