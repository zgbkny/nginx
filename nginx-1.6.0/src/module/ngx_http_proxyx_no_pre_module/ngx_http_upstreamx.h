/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAMX_H_INCLUDED_
#define _NGX_HTTP_UPSTREAMX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


//ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstreamx_init(ngx_http_request_t *r);


//ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
  //  ngx_url_t *u, ngx_uint_t flags);
//char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
 //   void *conf);
//char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
 //   void *conf);
//ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
 //   ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
 //   ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);

#endif /* _NGX_HTTP_UPSTREAMX_H_INCLUDED_ */
