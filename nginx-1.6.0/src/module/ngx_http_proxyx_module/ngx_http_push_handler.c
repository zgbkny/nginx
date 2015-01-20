#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_push_handler.h"

ngx_int_t 
ngx_http_push_handle(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_chain_t             *cl;
    ngx_buf_t               *buffer;
    ngx_int_t                fd;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle uri:%s", r->uri.data);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle request_body_in_file_only:%d", r->request_body_in_file_only);


    if (r->headers_in.content_length) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle content_length:%s", r->headers_in.content_length->value.data);
    }


    if (r->request_body) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle:");


        if (r->request_body->temp_file) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle file:%s", r->request_body->temp_file->file.name.data);
            return NGX_DONE;
        } else {
            cl = r->request_body->bufs;
            while (cl) {
                buffer = cl->buf;
                if (buffer) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle data:%d:%s", buffer->last - buffer->pos, buffer->pos);
                }
                cl = cl->next;
            }
        }

        cl = r->request_body->bufs;
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