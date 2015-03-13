#ifndef NGX_TCPX_H_INCLUDED_
#define NGX_TCPX_H_INCLUDED_


typedef struct {
    void                **main_conf;
    void                **srv_conf;
} ngx_tcpx_conf_ctx_t;




typedef struct {

    void                *(*create_main_conf)(ngx_conf_t *cf);
    char                *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                *(*create_srv_conf)(ngx_conf_t *cf);
    char                *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_tcpx_module_t;

#define NGX_TCPX_MODULE  0x00504355     /* TCPX */

extern ngx_module_t ngx_tcpx_module;

#endif /*NGX_TCPX_H_INCLUDED_*/