

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_tcpx.h"

static char *
ngx_tcpx_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_uint_t ngx_tcpx_max_module;

static ngx_command_t ngx_tcpx_commands[] = {
    {   ngx_string("tcpx"),
        NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
        ngx_tcpx_block,
        0,
        0,
        NULL },

    ngx_null_command
};

static ngx_core_module_t ngx_tcpx_module_ctx = {
    ngx_string("tcpx"),
    NULL,
    NULL
};

ngx_module_t ngx_tcpx_module = {
    NGX_MODULE_V1,
    &ngx_tcpx_module_ctx,           /*module context*/
    ngx_tcpx_commands,              /*module type*/
    NGX_CORE_MODULE,                /*module type*/
    NULL,                           /*init master*/
    NULL,                           /*init module*/
    NULL,                           /*init process*/
    NULL,                           /*init thread*/
    NULL,                           /*exit thread*/
    NULL,                           /*exit process*/
    NULL,                           /*exit master*/
    NGX_MODULE_V1_PADDING
};


static char *
ngx_tcpx_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_uint_t                       i, mi;
    ngx_tcpx_conf_ctx_t             *ctx;

    printf("tcp block");

    /* the main tcp context */
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcpx_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    } 
    *(ngx_tcpx_conf_ctx_t **)conf = ctx;

    /* count the number of the tcpx module and set up their indices */

    ngx_tcpx_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_TCPX_MODULE) {
            continue;
        }

        ngx_modules[i]->ctx_index = ngx_tcpx_max_module++;
    }

    /* the tcpx main_conf context, it is the same in the all tcpx contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcpx_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* the tcpx srv_conf context*/

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcpx_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* create the main_conf's srv_conf's */
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_TCPX_MODULE) {
            continue;
        }
        module = ngx_modules[i]->ctx;
        mi = ngx_modules[i]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}
