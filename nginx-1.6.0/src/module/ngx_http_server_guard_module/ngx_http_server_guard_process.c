#include "ngx_http_server_guard_module.h"
#include "ngx_http_server_guard_process.h"
#include "ngx_http_tcp_reuse_pool.h"
#include "ngx_http_server_guard_handler.h"
#include "ngx_http_tcp_reuse_upstream.h"

#define dd printf

//static ngx_msec_t check_timeout = 3000; // ms

//static ngx_event_t check_event;

static ngx_connection_t dummy;  

static ngx_event_t delay_ev;   

//static void ngx_http_server_guard_process_handler();

static ngx_int_t ngx_http_server_guard_send_delay_request(ngx_http_request_t *r);

static ngx_int_t ngx_http_server_guard_create_request(ngx_http_request_t *r);

static void ngx_http_server_guard_process_delay(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_processing(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_done(ngx_http_request_t *r, size_t id);

static void ngx_http_server_guard_process_error(ngx_http_request_t *r, size_t id);






static void ngx_http_server_guard_delay_timeout_handler(ngx_event_t *ev)   
{  
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ngx_http_server_guard_delay_timeout_handler");
  
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
    r->start_msec = ngx_current_msec;
	ngx_http_server_guard_send_delay_request(r);	
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

    if (myctx == NULL) {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_server_guard_ctx_t));
        if (myctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, myctx, ngx_http_server_guard_module);

        // set backend server
        myctx->backend_server = mycf->backend_server;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
    	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request upstream create error");

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

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request check4");


    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)80);
    pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request check3");


    backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request check2:%s", pDmsIP);

    myctx->backend_server.data = (u_char *)pDmsIP;
    myctx->backend_server.len = strlen(pDmsIP);



    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request check1");


    u->create_request = ngx_http_server_guard_create_request;
    u->process_header = ngx_http_tcp_reuse_process_header;
    u->finalize_request = ngx_http_tcp_reuse_finalize_request;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request check");


//    u->input_filter_init = ngx_http_server_guard_input_filter_init;
//    u->input_filter = ngx_http_server_guard_input_filter;
    u->input_filter_ctx = r;

    r->main->count++;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_send_delay_request before init upstream");

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

static void ngx_http_server_guard_process_processing(ngx_http_request_t *r, size_t id)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_processing");
}

static void ngx_http_server_guard_process_done(ngx_http_request_t *r, size_t id)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_done");
}

static void ngx_http_server_guard_process_error(ngx_http_request_t *r, size_t id)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_server_guard_process_error");
}
