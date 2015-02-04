#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_push_handler.h"

static u_char  ngx_http_file_cache_key[] = { LF, 'K', 'E', 'Y', ':', ' ' };


ngx_int_t
ngx_create_file(ngx_file_t *file, ngx_path_t *path, ngx_pool_t *pool,
    ngx_uint_t persistent, ngx_uint_t clean, ngx_uint_t access)
{
    ngx_err_t                 err;
    ngx_pool_cleanup_t       *cln;
    ngx_pool_cleanup_file_t  *clnf;


#if 0
    for (i = 0; i < file->name.len; i++) {
         file->name.data[i] = 'X';
    }
#endif

    cln = ngx_pool_cleanup_add(pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }
    for ( ;; ) {

        ngx_create_hashed_filename(path, file->name.data, file->name.len);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "hashed path: %s", file->name.data);

        file->fd = ngx_open_tempfile(file->name.data, persistent, access);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "temp fd:%d", file->fd);

        if (file->fd != NGX_INVALID_FILE) {

            cln->handler = clean ? ngx_pool_delete_file : ngx_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = file->fd;
            clnf->name = file->name.data;
            clnf->log = pool->log;

            return NGX_OK;
        }

        err = ngx_errno;

        if (err == NGX_EEXIST) {
           // n = (uint32_t) ngx_next_temp_number(1);
            return NGX_ERROR;
        }

        if ((path->level[0] == 0) || (err != NGX_ENOPATH)) {
            ngx_log_error(NGX_LOG_CRIT, file->log, err,
                          ngx_open_tempfile_n " \"%s\" failed",
                          file->name.data);
            return NGX_ERROR;
        }

        if (ngx_create_path(file, path) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
}


ngx_int_t 
ngx_http_push_handle(ngx_http_request_t *r, ngx_int_t rc)
{
    //return rc;
    ngx_chain_t                         *cl;
    ngx_buf_t                           *buffer = NULL;
    ngx_http_file_cache_header_t        *h;
    time_t                               valid;
    size_t                               body_start = 0;
    u_char                               flag[5] = {CR, LF, CR, LF, 0};
    ngx_int_t                            i = 0;
    ngx_str_t                           *key;
    ngx_uint_t                           j = 0;
    ssize_t                              total;

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
                if (buffer->in_file) {
                    return rc;
                } else {
                    

                    for (i = 0; i < buffer->last - buffer->pos; i++) {
                        if (ngx_strncmp(buffer->pos + i, flag, 4) == 0) {
                            goto find;
                        }
                    }
                    return rc;
                }

                if (buffer) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_push_handle data:%d:%s", buffer->last - buffer->pos, buffer->pos);
                }
                cl = cl->next;
            }

find:
            if (!buffer) {
                return rc;
            }
            body_start = i + 4;

            h = ngx_palloc(r->pool, sizeof(ngx_http_file_cache_header_t));
            if (h == NULL) {
                return rc;
            }
            valid = ngx_http_file_cache_valid(r->upstream->conf->cache_valid, 0);
            if (valid) {

            } else {

            }
            h->valid_sec = ngx_time() + valid;
            h->last_modified = ngx_time();
            h->date = ngx_time();
            h->crc32 = r->cache->crc32;
            h->valid_msec = (u_short)10;
            h->header_start = r->cache->header_start;
            h->body_start = h->header_start + body_start;

            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return rc;
            }

            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "push handle uri:%s", r->uri.data);

            buffer = ngx_create_temp_buf(r->pool, sizeof(ngx_http_file_cache_header_t) + r->uri.len + 100);

            if (buffer == NULL) {
                return rc;
            }
            cl->buf = buffer;
            ngx_memcpy(buffer->last, h, sizeof(ngx_http_file_cache_header_t));
            buffer->last += sizeof(ngx_http_file_cache_header_t);
            ngx_memcpy(buffer->last, ngx_http_file_cache_key, sizeof(ngx_http_file_cache_key));
            buffer->last += sizeof(ngx_http_file_cache_key);

            key = r->cache->keys.elts;
            for (j = 0; j < r->cache->keys.nelts; j++) {
                ngx_memcpy(buffer->last, key[j].data, key[j].len);
                buffer->last += key[j].len;
            }
            *(buffer->last) = LF;
            buffer->last += 1;   

            cl->next = r->request_body->bufs;
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "push handle fd:%d, %s", r->cache->file.fd, r->cache->file.name.data);
            if (r->cache->file.fd == -1) {
                ngx_create_file(&r->cache->file, r->cache->file_cache->path, r->pool, 1, 0, 0700);

                //r->cache->file.fd = open((const char*)r->cache->file.name.data, O_RDWR,  O_CREAT | O_EXCL | O_TRUNC);
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "push handle errno:%d", rc);

                if (r->cache->file.fd == -1) {
                    return rc;
                }
            }

            total = ngx_write_chain_to_file(&r->cache->file, cl, 0, r->pool);

            ngx_close_file(r->cache->file.fd);
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "push handle write total:%d", total);

            r->main->count = 1;

            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "push handle main:%d", r->main->count);
            return NGX_OK;
        }
    } else {
        goto next;
    }

next:    
    return rc;
}