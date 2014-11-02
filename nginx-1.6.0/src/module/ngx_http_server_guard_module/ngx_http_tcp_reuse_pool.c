#include "ngx_http_tcp_reuse_pool.h"
#include "ngx_http_server_guard_process.h"


#define ngx_tcp_reuse_requests_init_size 100
#define ngx_tcp_reuse_pool_size 409600
#define ngx_tcp_reuse_conns_init_size 100
#define ngx_tcp_reuse_request_pool_size 102400

static ngx_pool_t 		*ngx_reuse_pool;

static ngx_array_t 		 conns;

static ngx_array_t       requests;

static ngx_queue_t       empty_conns;

static ngx_queue_t       active_conns;

static ngx_queue_t		 empty_requests;

static ngx_queue_t       delay_requests;

static ngx_queue_t 		 processing_requests;

static ngx_queue_t 		 done_requests;

static ngx_queue_t 	     error_requests;

static int active_conns_count;

static int delay_requests_count;

//static int wait_requests_count;



static void ngx_tcp_reuse_event_handler(ngx_event_t *ev);

static void ngx_tcp_reuse_read_handler(ngx_tcp_reuse_conn_t *reuse_conn);

static void ngx_tcp_reuse_write_handler(ngx_tcp_reuse_conn_t *reuse_conn);

void ngx_tcp_reuse_statistic()
{

}

// ret val:second
size_t ngx_tcp_reuse_get_queue_time()
{
	return 7;
}

int ngx_tcp_reuse_pool_init(ngx_log_t *log)
{

	ngx_reuse_pool = ngx_create_pool(ngx_tcp_reuse_pool_size, log);
	if (ngx_reuse_pool == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "could not create ngx_reuse_pool");
		exit(1);
	}

	conns.elts = ngx_pcalloc(ngx_reuse_pool, ngx_tcp_reuse_conns_init_size * sizeof (ngx_tcp_reuse_conn_t));
	conns.nelts = 0;
	conns.size = sizeof (ngx_tcp_reuse_conn_t);
	conns.nalloc = ngx_tcp_reuse_conns_init_size;
	conns.pool = ngx_reuse_pool;

	requests.elts = ngx_palloc(ngx_reuse_pool, ngx_tcp_reuse_requests_init_size * sizeof (ngx_tcp_reuse_request_t));
	requests.nelts = 0;
	requests.size = sizeof (ngx_tcp_reuse_request_t);
	requests.nalloc = ngx_tcp_reuse_requests_init_size;
	requests.pool = ngx_reuse_pool;

	ngx_queue_init(&empty_conns);
	ngx_queue_init(&active_conns);
	ngx_queue_init(&delay_requests);
	ngx_queue_init(&empty_requests);
	ngx_queue_init(&processing_requests);
	ngx_queue_init(&done_requests);
	ngx_queue_init(&error_requests);
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_tcp_reuse_pool_init ok");
	return NGX_OK;
}


ngx_socket_t ngx_tcp_reuse_get_active_conn(ngx_log_t *log)
{
	ngx_socket_t fd = -1;
	ngx_err_t    err;
	u_char test[2];
	while (!ngx_queue_empty(&active_conns)) {
		ngx_queue_t *head_conn = ngx_queue_head(&active_conns);
		ngx_tcp_reuse_conn_t *active_conn = ngx_queue_data(head_conn, ngx_tcp_reuse_conn_t, q_elt);
		fd = active_conn->fd;
		if (active_conn->read.timer_set) {
			ngx_del_timer(&active_conn->read);
		}
		if (active_conn->write.timer_set) {
			ngx_del_timer(&active_conn->write);
		}
		if (active_conn->read.active) {
			ngx_del_event(&active_conn->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
		}
		if (active_conn->write.active) {
			ngx_del_event(&active_conn->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
		}
		ngx_queue_remove(&active_conn->q_elt);
		ngx_memzero(active_conn, sizeof(ngx_tcp_reuse_conn_t));
		ngx_queue_insert_tail(&empty_conns, &active_conn->q_elt);

		if (recv(fd, test, 0, 0) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "0 : errno:%d, %s", ngx_socket_errno, strerror(errno));
			close(fd);
			fd = -1;
		} else {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "!0 : errno:%d, %s", ngx_socket_errno, strerror(errno));
			err = ngx_socket_errno;
			if (err == 11)
				break;
			else {
				close(fd);
				fd = -1;
			}
		}
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "fd:%d", fd);

		active_conns_count--;

	}
	return fd;
}

int ngx_tcp_reuse_put_active_conn(ngx_socket_t fd, ngx_log_t *log)
{
	ngx_tcp_reuse_conn_t *new_conn = NULL;
	ngx_queue_t *head = NULL;
	if (ngx_queue_empty(&empty_conns)) {
		new_conn = ngx_array_push(&conns);	
		if (new_conn == NULL) {
			return NGX_ERROR;
		}
	} else {
		head = ngx_queue_head(&empty_conns);
		new_conn = ngx_queue_data(head, ngx_tcp_reuse_conn_t, q_elt);
		ngx_queue_remove(&new_conn->q_elt);
	}
	ngx_queue_insert_tail(&active_conns, &new_conn->q_elt);
	new_conn->fd = fd;
	new_conn->read_event_handler = ngx_tcp_reuse_read_handler;
	new_conn->write_event_handler = ngx_tcp_reuse_write_handler;
	new_conn->read.handler = ngx_tcp_reuse_event_handler;
	new_conn->write.handler = ngx_tcp_reuse_event_handler;


	active_conns_count++;
	return NGX_OK;
}

size_t ngx_tcp_reuse_get_request_state(size_t id)
{
	ngx_tcp_reuse_request_t 	*requests_array = requests.elts;
	if (id < requests.nelts) {
		return requests_array[id].state;
	} else {
		return NGX_ERROR;
	}
}

int ngx_tcp_reuse_put_delay_request(ngx_http_request_t *r, int *id)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_tcp_reuse_put_delay_request");


	ngx_tcp_reuse_request_t 		*new_request = NULL;
	ngx_queue_t 					*head = NULL;
    size_t                           len = 0;
	ngx_list_part_t                 *part;
    ngx_table_elt_t                 *header;
    ngx_buf_t 						*b;
    ngx_chain_t                     *cl, *body;//, *body;
    size_t 							 i;

	if (ngx_queue_empty(&empty_requests)) {
		new_request = ngx_array_push(&requests);
		if (new_request == NULL) {
			return NGX_ERROR;
		}
	} else {
		head = ngx_queue_head(&empty_requests);
		new_request = ngx_queue_data(head, ngx_tcp_reuse_request_t, q_elt);
		ngx_queue_remove(&new_request->q_elt);
	}

	ngx_queue_insert_tail(&delay_requests, &new_request->q_elt);
	

	/*------------------------------------*/
	new_request->data = NULL;
	new_request->state = DELAY;
	new_request->second_r = NULL;
	new_request->done_handler = NULL;
	new_request->error_handler = NULL;
	/**************************************/


	new_request->log = ngx_cycle->log;
	new_request->pool = ngx_create_pool(ngx_tcp_reuse_request_pool_size, new_request->log);

	len += r->request_line.len + 2;
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        
        if (!ngx_strcmp(header[i].key.data, "Connection")) {
            header[i].value.data = (u_char *)KEEPALIVE;
            header[i].value.len = 10;
        }
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "key:%s, value:%s", header[i].key.data, header[i].value.data);
        
        len += header[i].key.len + sizeof(": ")
             + header[i].value.len + sizeof(CRLF);
    }
    len += sizeof(CRLF);
    //len += r->headers_in.content_length_n;

    b = ngx_create_temp_buf(new_request->pool, len);
    
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(new_request->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }



    cl->buf = b;

    new_request->cl = cl;

    
    b->last = ngx_copy(b->last, r->request_line.data, r->request_line.len);
    *b->last++ = CR; *b->last++ = LF;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';
        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    *b->last++ = CR; *b->last++ = LF;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_tcp_reuse_put_delay_request just before body, body length:%d", r->headers_in.content_length_n);

    body = NULL;
    if (r->request_body) {
    	body = r->request_body->bufs;    	
    }

    while (body) {


        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "body:%s", body->buf->start);
        b = ngx_alloc_buf(new_request->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
        // this is a big bug
        ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));
        cl->next = ngx_alloc_chain_link(new_request->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->buf = b;
        body = body->next;
    }
    cl->next = NULL;
    b->flush = 1;


	//set id
	*id = new_request - (ngx_tcp_reuse_request_t *)requests.elts;

	delay_requests_count++;
	return NGX_OK;
}

int ngx_tcp_reuse_process_delay_request(ngx_http_request_t *r, size_t id)
{
	ngx_chain_t              *cl = NULL, *new_cl = NULL;
	ngx_tcp_reuse_request_t  *trr = requests.elts;
	int  				      len = 0;
	ngx_buf_t  				 *b, *new_b;

	
	if (id >= requests.nelts) {
		return NGX_ERROR;
	}

	trr = &trr[id];

	if (trr->state != DELAY) {
		return NGX_ERROR;
	} 
	new_cl = ngx_alloc_chain_link(r->pool);
	if (new_cl == NULL) {
		return NGX_ERROR;
	}
	new_cl->next = NULL;

	r->out = new_cl;
	cl = trr->cl;
	while (cl) {
		b = cl->buf;
		len = b->last - b->start;
		new_b = ngx_create_temp_buf(r->pool, len);
		new_b->last = ngx_copy(new_b->last, b->start, len);
		new_cl->next = ngx_alloc_chain_link(r->pool);
		new_cl = new_cl->next;
		new_cl->buf = new_b;
		cl = cl->next;

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, trr->log, 0, "buf:%s", new_b->start);
	}
	new_cl->next = NULL;
	r->out = r->out->next;

	trr->state = 0;
	trr->cl = NULL;

	ngx_destroy_pool(trr->pool);
	ngx_queue_remove(&trr->q_elt);
	ngx_queue_insert_tail(&empty_requests, &trr->q_elt);


	return NGX_OK;
}


//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------


void *ngx_tcp_reuse_get_delay_request()
{
	ngx_http_request_t *r = NULL;

	if (!ngx_queue_empty(&delay_requests)) {
		ngx_queue_t *head_request = ngx_queue_head(&delay_requests);
		ngx_tcp_reuse_request_t *trr = ngx_queue_data(head_request, ngx_tcp_reuse_request_t, q_elt);
		r = trr->data;
		// use limit_rate to save id in requests;
		r->limit_rate = trr - (ngx_tcp_reuse_request_t *)requests.elts;
		trr->state = PROCESSING;

		ngx_queue_remove(&trr->q_elt);
		//ngx_memzero(trr, sizeof(ngx_tcp_reuse_request_t));
		ngx_queue_insert_tail(&processing_requests, &trr->q_elt);
	}
	return r;
}

void ngx_tcp_reuse_move_request_from_processing_to_done(size_t id)
{
	ngx_tcp_reuse_request_t *trr = (ngx_tcp_reuse_request_t *)requests.elts;
	trr = &trr[id];
	trr->state = DONE;
	ngx_queue_remove(&trr->q_elt);
	ngx_queue_insert_tail(&done_requests, &trr->q_elt);

	if (trr->second_r) {
		trr->done_handler(trr->data, trr->second_r);
		ngx_queue_remove(&trr->q_elt);
		ngx_queue_insert_tail(&empty_requests, &trr->q_elt);
	}
}

void ngx_tcp_reuse_check_update(size_t id)
{
	ngx_tcp_reuse_request_t *trr = (ngx_tcp_reuse_request_t *)requests.elts;
	trr = trr + id;
	if (trr->state != DONE) {
		trr->state = ERROR;
	}
	ngx_queue_remove(&trr->q_elt);
	ngx_queue_insert_tail(&error_requests, &trr->q_elt);	

	if (trr->second_r) {
		trr->error_handler(trr->data, trr->second_r);
		ngx_queue_remove(&trr->q_elt);
		ngx_queue_insert_tail(&error_requests, &trr->q_elt);
	}
}

void *ngx_tcp_reuse_get_processing_request()
{
	ngx_http_request_t *r = NULL;

	if (!ngx_queue_empty(&processing_requests)) {
		ngx_queue_t *head_request = ngx_queue_head(&processing_requests);
		ngx_tcp_reuse_request_t *trr = ngx_queue_data(head_request, ngx_tcp_reuse_request_t, q_elt);
		r = trr->data;
	}
	return r;
}

int ngx_tcp_reuse_check_processing_request_by_id(size_t id)
{
	ngx_tcp_reuse_request_t *requests_array = requests.elts;
	ngx_http_request_t      *r = requests_array[id].data;
	if (r->out) {
		return NGX_OK;
	} else 
		return NGX_ERROR;
}


void *ngx_tcp_reuse_delay_request_head()
{
	return NULL;
}

void *ngx_tcp_reuse_processing_request_head()
{
	return NULL;
}

void *ngx_tcp_reuse_done_request_head()
{
	return NULL;
}

void *ngx_tcp_reuse_get_request_by_id(size_t id)
{
	ngx_tcp_reuse_request_t *requests_array = requests.elts;
	ngx_http_request_t      *r = requests_array[id].data;
	ngx_queue_remove(&(requests_array[id].q_elt));
	ngx_queue_insert_tail(&empty_requests, &(requests_array[id].q_elt));
	return r;
}

void ngx_tcp_reuse_set_done_and_error_handler(size_t id, ngx_http_request_t *r, ngx_delay_request_handler_pt done_handler, ngx_delay_request_handler_pt error_handler)
{
	ngx_tcp_reuse_request_t *trr = requests.elts;
	trr = &trr[id];
	trr->second_r = r;
	trr->done_handler = done_handler;
	trr->error_handler = error_handler;
}


static void ngx_tcp_reuse_event_handler(ngx_event_t *ev)
{
	ngx_tcp_reuse_conn_t *reuse_conn;
	reuse_conn = ev->data;

	if (ev->write) {
		reuse_conn->write_event_handler(reuse_conn);
	} else {
		reuse_conn->read_event_handler(reuse_conn);
	}
}

static void ngx_tcp_reuse_read_handler(ngx_tcp_reuse_conn_t *reuse_conn)
{

}

static void ngx_tcp_reuse_write_handler(ngx_tcp_reuse_conn_t *reuse_conn)
{

}	