

void ngx_http_tcp_reuse_upstream_init(ngx_http_request_t *r)
{
	ngx_connection_t 		*c;

	c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http init upstream, client timer: %d", c->read->timer_set);

    if (c->read->timer_set) {
    	ngx_del_timer(c->read);
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
    	if (!c->write->active) {
    		if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
    			== NGX_ERROR)
    		{
    			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    			return;
    		}
    	}
    }

    ngx_http_tcp_upstream_init_request(r);
}

void ngx_http_tcp_upstream_init_request(ngx_http_request_t *r) 
{
	ngx_str_t 						*host;
	ngx_uint_t 				 	 	 i;
	ngx_resolver_ctx_t				*ctx, temp;
	ngx_http_cleanup_t				*cln;
	ngx_http_upstream_t 			*u;
	ngx_http_core_loc_conf_t		*clcf;
	ngx_http_upstream_srv_conf_t	*uscf, **uscfp;
	ngx_http_upstream_main_conf_t	*umcf;

	if (r->aio) {
		
	}
}

