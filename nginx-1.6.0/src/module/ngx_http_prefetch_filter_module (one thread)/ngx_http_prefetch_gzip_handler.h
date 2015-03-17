#ifndef NGX_HTTP_PREFETCH_GZIP_HANDLER_H
#define NGX_HTTP_PREFETCH_GZIP_HANDLER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <zlib.h>
void
ngx_http_prefetch_gzip_test();

int
ngx_http_prefetch_gzip_decompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);

#endif /*NGX_HTTP_PREFETCH_GZIP_HANDLER_H*/