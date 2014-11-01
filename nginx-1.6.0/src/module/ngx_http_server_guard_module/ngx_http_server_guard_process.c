
#include "ngx_http_server_guard_process.h"
#include "ngx_http_tcp_reuse_pool.h"
#include "ngx_http_server_guard_handler.h"

#define dd printf

//static ngx_msec_t check_timeout = 3000; // ms

//static ngx_event_t check_event;

static ngx_connection_t dummy;  

static ngx_event_t delay_ev;   

static ngx_event_t processing_ev;

//static void ngx_http_server_guard_process_handler();

static ngx_int_t ngx_http_server_guard_send_delay_request(ngx_http_request_t *r);

static ngx_int_t ngx_http_server_guard_create_request(ngx_http_request_t *r);

static void ngx_http_server_guard_process_delay(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_processing(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_done(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_error(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_merge_request(ngx_http_request_t *r, ngx_http_request_t *second_r);

static void ngx_http_server_guard_done_handler(ngx_http_request_t *r, ngx_http_request_t *second_r);

static void ngx_http_server_guard_error_handler(ngx_http_request_t *r, ngx_http_request_t *second_r);


int check_overload()
{
	static int i = 5;
	i++;
	if (i > 1) 
		return SERVER_OVERLOAD;
	else 
		return SERVER_NOTOVERLOAD;
}

void ngx_http_server_guard_close_connection(ngx_connection_t *c)
{
	//ngx_err_t 			err;
	//ngx_uint_t			log_error;
	ngx_socket_t   		fd;

	if (c->fd == (ngx_socket_t)-1) {
		ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection closed");
		return;
	}
	if (c->read->timer_set) {
		ngx_del_timer(c->read);
	}
	if (c->write->timer_set) {
		ngx_del_timer(c->write);
	}

	if (ngx_del_conn) {
		ngx_del_conn(c, NGX_CLOSE_EVENT);
	} else {
		if (c->read->active || c->read->disabled) {
			ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
		}

		if (c->write->active || c->write->disabled) {
			ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
		}
	}

	if (c->read->prev) {
		ngx_delete_posted_event(c->read);
	}

	if (c->write->prev) {
		ngx_delete_posted_event(c->write);
	}
	c->read->closed = 1;
	c->write->closed = 1;

	//ngx_reusable_connection(c, 0);

	//log_error = c->log_error;

	//ngx_free_connection(c);

	fd = c->fd;
	c->fd = (ngx_socket_t)-1;
	ngx_close_socket(fd);

}

void ngx_http_server_guard_release_connection(ngx_connection_t *c)
{
	if (c->reusable) {
		ngx_queue_remove(&c->queue);
	}
	c->write->active = 0;
	c->reusable = 0;

	ngx_free_connection(c);
}



static void ngx_http_server_guard_processing_timeout_handler(ngx_event_t *ev)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_server_guard_processing_timeout_handler");
	ngx_http_request_t *r = ngx_tcp_reuse_get_processing_request();
  	if (r) {
  		ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "r->out:%d", r->out);
  	}
	//ngx_add_timer(ev, 1000);
}

static void ngx_http_server_guard_delay_timeout_handler(ngx_event_t *ev)   
{  
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_server_guard_delay_timeout_handler");
  
  	ngx_http_request_t *r = ngx_tcp_reuse_get_delay_request();
  	if (r) {
  		r->connection->write->active = 1;
  		r->subrequest_in_memory = 1;  
  		ngx_http_server_guard_normal(r);  
  	}

    //ngx_add_timer(ev, 1000);

}  

void ngx_http_server_guard_init()
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "server_guard_init");
	dummy.fd = (ngx_socket_t) -1;   
  
    //ngx_memzero(&delay_ev, sizeof(ngx_event_t));  
  
    delay_ev.handler = ngx_http_server_guard_delay_timeout_handler;  
    delay_ev.log = ngx_cycle->log;  
    delay_ev.data = &dummy;  

  	if (!delay_ev.timer_set) {
    	//ngx_add_timer(&delay_ev, 10000);
    } 
    
    // - - - - - - - - -

    //ngx_memzero(&processing_ev, sizeof(ngx_event_t));  
  
    processing_ev.handler = ngx_http_server_guard_processing_timeout_handler;  
    processing_ev.log = ngx_cycle->log;  
    processing_ev.data = &dummy;  
  	if (!processing_ev.timer_set) {
    //	ngx_add_timer(&processing_ev, 5000); 
    }
}
  

void ngx_http_server_guard_process(ngx_http_request_t *r)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process");
	ngx_chain_t 			*cl = r->request_body->bufs;
	ngx_buf_t 				*buf;
	int						 id = -1;


	// should use a new buf to store all request body
	while (cl) {
		buf = cl->buf;
		id = ngx_atoi(buf->start, buf->last - buf->start);
		cl = cl->next;
	}
	// also need to check request content
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process state:%d", ngx_tcp_reuse_get_request_state(id));
	switch(ngx_tcp_reuse_get_request_state(id)) {


	case DELAY:
		ngx_http_server_guard_process_delay(r, id);
		break;
	case PROCESSING:
		ngx_http_server_guard_process_processing(r, id);
		break;
	case DONE:
		ngx_http_server_guard_process_done(r, id);
		break;
	default:// we need to process invalid request
		ngx_http_server_guard_process_error(r, id);
		break;
	}
}
/*
static void ngx_http_server_guard_process_handler()
{
	//ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_server_guard_process_handler");
	ngx_http_request_t *r = ngx_tcp_reuse_get_delay_request();
	if (r) {
		r->subrequest_in_memory = 1;
		ngx_http_server_guard_normal(r);
		//r = ngx_tcp_reuse_get_delay_request();
	}
}*/

// this is the handler when reqeust is not handle 
static void ngx_http_server_guard_process_delay(ngx_http_request_t *r, size_t id)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_delay");
	ngx_tcp_reuse_process_delay_request(r, id);
	
	if (r->out == NULL) {
		// error here;
		return;
	}
	// request is save in r->out, now it can be send to server

}

static ngx_int_t ngx_http_server_guard_send_delay_request(ngx_http_request_t *r)
{
    //ngx_int_t                        rc;
    ngx_http_server_guard_ctx_t     *myctx;
    ngx_http_server_guard_conf_t    *mycf;
    ngx_http_upstream_t             *u;
    static struct sockaddr_in        backendSockAddr;
    struct hostent                  *pHost;
    char                            *pDmsIP;
    
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request");

    mycf = ngx_http_get_module_loc_conf(r, ngx_http_server_guard_module);
    // get http ctx's ngx_http_server_guard_ctx_t
    myctx = ngx_http_get_module_ctx(r, ngx_http_server_guard_module);


    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_ERROR;
    }

    u = r->upstream;
    u->conf = &mycf->upstream;
    u->buffering = mycf->upstream.buffering;

    u->resolved = (ngx_http_upstream_resolved_t *)ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }


    pHost = gethostbyname((char *)mycf->backend_server.data);
    if (pHost == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }

    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)80);
    pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));

    backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backend_server.data = (u_char *)pDmsIP;
    myctx->backend_server.len = strlen(pDmsIP);

    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;

    u->create_request = ngx_http_server_guard_create_request;
    u->process_header = ngx_http_tcp_reuse_process_header;
    u->finalize_request = ngx_http_tcp_reuse_finalize_request;

//    u->input_filter_init = ngx_http_server_guard_input_filter_init;
//    u->input_filter = ngx_http_server_guard_input_filter;
    u->input_filter_ctx = r;

    r->main->count++;
    ngx_http_tcp_reuse_upstream_init(r);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request r->main :%d", r->main->count);
    
    return NGX_DONE;
}


static ngx_int_t ngx_http_server_guard_create_request(ngx_http_request_t *r)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_create_request");

    ngx_http_upstream_t             *u;    
    u = r->upstream;

    u->request_bufs = r->out;
    r->out = NULL;

    return NGX_OK;
}








//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

//------------------------------------------------------------------

static void ngx_http_server_guard_process_processing(ngx_http_request_t *r, size_t id)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_processing");
}

static void ngx_http_server_guard_process_done(ngx_http_request_t *r, size_t id)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_done");

	ngx_http_request_t *origin_r = NULL;
	//if (ngx_tcp_reuse_check_processing_request_by_id(id) == NGX_OK) {
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_done");

	origin_r = ngx_tcp_reuse_get_request_by_id(id);
	ngx_http_server_guard_merge_request(origin_r, r);
	//}
}

static void ngx_http_server_guard_process_error(ngx_http_request_t *r, size_t id)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_error");
	ngx_tcp_reuse_get_request_by_id(id);
	r->main->count = 1;
	ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}

static void ngx_http_server_guard_done_handler(ngx_http_request_t *r, ngx_http_request_t *second_r)
{

}

static void ngx_http_server_guard_error_handler(ngx_http_request_t *r, ngx_http_request_t *second_r)
{

}

static void ngx_http_server_guard_merge_request(ngx_http_request_t *r, ngx_http_request_t *second_r)
{
	ngx_int_t rc;
	ngx_chain_t *data = r->out;
	r->out = NULL;
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_merge_request ");
	r->connection->fd = second_r->connection->fd;
	second_r->connection->fd = (ngx_socket_t)-1;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_merge_request ??");
    r->header_sent = 0;
	rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    }
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_merge_request check");
	
    rc = ngx_http_output_filter(r, data);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_merge_request 1");
	

    //r->main->count = 1;
    ngx_http_finalize_request(r, rc);
    second_r->main->count = 1;
    ngx_http_finalize_request(r, NGX_DONE);
}
