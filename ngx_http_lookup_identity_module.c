#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <dbus/dbus.h>

typedef struct {
    ngx_flag_t  active;
    ngx_str_t   output;          
    ngx_str_t   gecos;
    ngx_str_t   groups;
    ngx_str_t   groups_i;
    ngx_str_t   attr;
    ngx_str_t   attr_i;
    ngx_uint_t  timeout;
} ngx_http_lookup_identity_loc_conf_t;

static ngx_int_t ngx_http_lookup_identity_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_lookup_identity_init(ngx_conf_t *cf);
static void *ngx_http_lookup_identity_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_lookup_identity_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t read_dbus(ngx_http_request_t *r, char *method, int timeout, char *attribute, ngx_array_t * output);

static ngx_int_t process_group_list(ngx_http_request_t *r, ngx_array_t *group_list, ngx_http_lookup_identity_loc_conf_t  *loc_conf);
static ngx_array_t * get_group_list(ngx_http_request_t *r, int timeout);
static DBusMessage * lookup_identity_dbus_message(ngx_http_request_t *r, DBusConnection * connection, DBusError * error, int timeout, const char * method, const char ** args);


#define lookup_identity_debug0(msg) ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg)
#define lookup_identity_debug1(msg, one) ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one)
#define lookup_identity_debug2(msg, one, two) ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one, two)
#define lookup_identity_log_error(fmt, args...) ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, fmt, ##args)

#define _DEFAULT_TIMEOUT 5000
#define _DEFAULT_OUTPUT "All"
#define _DEFAULT_GECOS "REMOTE_USER_GECOS"
#define _DEFAULT_GROUPS ""
#define _DEFAULT_GROUPS_I ""
#define _DEFAULT_ATTR ""
#define _DEFAULT_ATTR_I ""
#define _DEFAULT_SEPARATOR ""

#define DBUS_SSSD_GET_USER_GROUPS_METHOD "GetUserGroups"
#define DBUS_SSSD_GET_USER_ATTR_METHOD "GetUserAttr"

#define DBUS_SSSD_IFACE "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_DEST "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_PATH "/org/freedesktop/sssd/infopipe"


static ngx_command_t ngx_http_lookup_identity_commands[] = {
    { ngx_string("lookup_identity"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lookup_identity_loc_conf_t, active),
      NULL
    },

    { ngx_string("lookup_identity_output"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lookup_identity_loc_conf_t, output),
      NULL
    },

    { ngx_string("lookup_identity_gecos"),  
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lookup_identity_loc_conf_t, gecos),
      NULL
    },

    { ngx_string("lookup_identity_groups"),           
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lookup_identity_loc_conf_t, groups),
      NULL
    },

    { ngx_string("lookup_identity_groups_iter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lookup_identity_loc_conf_t, groups_i),
      NULL
    },

    { ngx_string("lookup_identity_attr"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lookup_identity_loc_conf_t, attr),
      NULL
    },

    { ngx_string("lookup_identity_attr_iter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lookup_identity_loc_conf_t, attr_i),
      NULL
    },

    { ngx_string("lookup_identity_dbus_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lookup_identity_loc_conf_t, timeout),
      NULL
    },

    ngx_null_command
};


static ngx_int_t ngx_http_lookup_identity_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_lookup_identity_handler;

    return NGX_OK;
}

static void * ngx_http_lookup_identity_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_lookup_identity_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lookup_identity_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->active = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_UINT;

    return conf;
}

static char * ngx_http_lookup_identity_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_lookup_identity_loc_conf_t *prev = parent;
    ngx_http_lookup_identity_loc_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->active, prev->active, 0);
    ngx_conf_merge_str_value(conf->output, prev->output, _DEFAULT_OUTPUT);
    ngx_conf_merge_uint_value(conf->timeout, prev->timeout, _DEFAULT_TIMEOUT);
    ngx_conf_merge_str_value(conf->gecos, prev->gecos, _DEFAULT_GECOS);
    ngx_conf_merge_str_value(conf->groups, prev->groups, _DEFAULT_GROUPS);
    ngx_conf_merge_str_value(conf->groups_i, prev->groups_i, _DEFAULT_GROUPS_I);
    ngx_conf_merge_str_value(conf->attr, prev->attr, _DEFAULT_ATTR);
    ngx_conf_merge_str_value(conf->attr_i, prev->attr_i, _DEFAULT_ATTR_I);

    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_lookup_identity_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_lookup_identity_init,      /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_lookup_identity_create_loc_conf,  /* create location configuration */
    ngx_http_lookup_identity_merge_loc_conf    /* merge location configuration */
};

ngx_module_t ngx_http_lookup_identity_module = {
    NGX_MODULE_V1,
    &ngx_http_lookup_identity_module_ctx,
    ngx_http_lookup_identity_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};   

static ngx_int_t insert_custom_header(ngx_http_request_t *r, ngx_keyval_t *keyval)
{
    ngx_table_elt_t *h;
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    lookup_identity_debug1("[LIM] Insert custom header name: %s", keyval->key.data);
    lookup_identity_debug1("[LIM] Insert custom header name: %d", keyval->key.len);
    lookup_identity_debug1("[LIM] Insert custom header value: %s", keyval->value.data);
    lookup_identity_debug1("[LIM] Insert custom header value: %d", keyval->value.len);

    h->key.data = keyval->key.data;
    h->key.len = keyval->key.len;
    h->value.data = keyval->value.data;
    h->value.len = keyval->value.len;

    h->hash = 1;

    return NGX_OK;
}

static ngx_str_t* ngx_str(ngx_http_request_t *r, const char *string)
{
    ngx_str_t *str = ngx_palloc(r->pool, sizeof(ngx_str_t));
    str->data = (u_char*) string;
    str->len = strlen(string);
    return str;    
}

static ngx_keyval_t* ngx_keyval(ngx_http_request_t *r, const ngx_str_t *key, const ngx_str_t *value)
{
    ngx_keyval_t *keyval = ngx_palloc(r->pool, sizeof(ngx_keyval_t));
    keyval->key = *key;

    keyval->value = *value;
    return keyval;
}

/*
 * Module handler
 *
 */
static ngx_int_t ngx_http_lookup_identity_handler(ngx_http_request_t *r)
{    
    ngx_http_lookup_identity_loc_conf_t  *loc_conf;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_lookup_identity_module); 

    if (loc_conf->active == 0) {
        return NGX_DECLINED;
    }
    
    if (r->headers_in.user.len == 0) {
        return NGX_DECLINED;
    }

    if (loc_conf->output.len == 0) {
        lookup_identity_log_error("Lookup identity: Output is not specified");
        return NGX_ERROR;
    }

    if (loc_conf->groups.len != 0) {
        if (loc_conf->groups.data[0] == '+') {
            lookup_identity_debug0("Append groups");
        }
    }

    ngx_str_t *attr_name;
    attr_name = ngx_str(r, "ATTR");
    ngx_str_t *attr_type;
    attr_type = ngx_str(r, "ATTR_TYPE");
    ngx_str_t *attr_sep;
    attr_sep = ngx_str(r, "ATTR_SEP");

    ngx_str_t *attr_i_name;
    attr_i_name = ngx_str(r, "ATTR_ITER");
    ngx_str_t *attr_i_type;
    attr_i_type = ngx_str(r, "ATTR_ITER_TYPE");

    int timeout = _DEFAULT_TIMEOUT; 
    if (loc_conf->timeout > 0) {
        timeout = loc_conf->timeout;
    }

    if (loc_conf->groups.len != 0 || loc_conf->groups_i.len != 0) {
        ngx_array_t *group_list;
        group_list = get_group_list(r, timeout);

        if (group_list != NULL) {
            /*lookup_identity_debug1("[LIM] Group list number of elts: %d", group_list->nelts);
            lookup_identity_debug1("[LIM] Group list element len: %d", (((ngx_str_t *) group_list->elts)[0].len));
            lookup_identity_debug1("[LIM] Group list element data: %s", (((ngx_str_t *) group_list->elts)[0].data)); */

            process_group_list(r, group_list, loc_conf); 
        }
    }

    if (attr_name->len != 0 || attr_i_name->len != 0) {
        
    }

    return NGX_OK;   
};


static ngx_int_t process_group_list(ngx_http_request_t *r, ngx_array_t *group_list, ngx_http_lookup_identity_loc_conf_t  *loc_conf) {

    char *separator = ":";

    if (loc_conf->groups.len > 0) {
        if (group_list->nelts <= 0) {
            if (insert_custom_header(r, ngx_keyval(r, &loc_conf->groups, ngx_str(r, ""))) != NGX_OK)
                return NULL;
        }
        else {
            if (strcmp(separator, "") != 0) {
                unsigned int n_char = group_list->nelts-1; //separators
                unsigned int i; 
                for (i = 0; i < group_list->nelts; i++) {
                    n_char += (((ngx_str_t *) group_list->elts)[i].len);
                }

                char *data = ngx_palloc(r->pool, n_char * sizeof(u_char));
                if (data == NULL) {
                    lookup_identity_log_error("Lookup Identity: Memory allocation failed");
                    return NULL;
                }

                for (i = 0; i < group_list->nelts; i++) {
                    if (i == 0) {
                        strcpy(data, (const char *)(((ngx_str_t *) group_list->elts)[i].data));
                    }
                    else {
                        strcat(data, separator);
                        strcat(data, (const char *)(((ngx_str_t *) group_list->elts)[i].data));
                    }    
                }

                if (insert_custom_header(r, ngx_keyval(r, &loc_conf->groups, ngx_str(r, data))) != NGX_OK)
                    return NULL;
            }
            else {
                if (insert_custom_header(r, ngx_keyval(r, &loc_conf->groups, &(((ngx_str_t *)group_list->elts)[0]))))
                    return NULL;
            }
        }
    }

    if (loc_conf->groups_i.len > 0) {

        /*"GROUPNAME_n: group_n" headers*/
        unsigned int i;
        for (i = 0; i < group_list->nelts; i++) {
            char *header_name = ngx_palloc(r->pool, loc_conf->groups.len * sizeof(u_char) + 3 * sizeof(char));
            if (header_name == NULL) {
                lookup_identity_log_error("Lookup Identity: Memory allocation failed");
                return NULL;
            }

            strcpy(header_name, (const char *) loc_conf->groups_i.data);
            strcat(header_name, "_");

            /*TODO: determine the number of digits*/
            char str [3];
            sprintf(str, "%d", (int) i);
            strcat(header_name, str);
            if (insert_custom_header(r, ngx_keyval(r, ngx_str(r, header_name), &(((ngx_str_t *)group_list->elts)[i]))))
                return NULL;
        }

        /* "GROUPNAME_N: number of groups" header */
        char *header_name = ngx_palloc(r->pool, loc_conf->groups.len * sizeof(u_char) + 3 * sizeof(char));
        if (header_name == NULL) {
            lookup_identity_log_error("Lookup Identity: Memory allocation failed");
            return NULL;
        }

        strcpy(header_name, (const char *) loc_conf->groups_i.data);
        strcat(header_name, "_N");

        /*TODO: determine the number of digits*/
        char str [3];
        sprintf(str, "%d", (int)group_list->nelts);
        if (insert_custom_header(r, ngx_keyval(r, ngx_str(r, header_name), ngx_str(r, str))))
            return NULL;
    }

    return NGX_OK;
}

static ngx_array_t * get_group_list(ngx_http_request_t *r, int timeout) {

    ngx_array_t *group_list;
    group_list = ngx_array_create(r->pool, 10, sizeof(ngx_str_t));
    if (group_list == NULL) {
        lookup_identity_log_error("Memory allocation failed.");
        return NULL;
    }   

    read_dbus(r, DBUS_SSSD_GET_USER_GROUPS_METHOD, timeout, NULL, group_list);

    return group_list;
}

/**/
static ngx_int_t read_dbus(ngx_http_request_t *r, char *method, int timeout, char * attribute, ngx_array_t *output) 
{
    DBusError error;
    dbus_error_init(&error);
    DBusConnection *connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    
    if (!connection) {
        lookup_identity_log_error("Lookup Identity: dbus connection failed");
    } 
    else {
        lookup_identity_debug0("[LIM] dbus connection created");
        dbus_connection_set_exit_on_disconnect(connection, FALSE);

        DBusMessage *reply = lookup_identity_dbus_message(r, connection, &error, timeout, method, NULL);

        if (reply != NULL) {
            int num;
            char **ptr;
            if (dbus_message_get_args(reply, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &ptr, &num, DBUS_TYPE_INVALID)) {
                u_char *data;
                int i;
                for (i = 0; i < num; i++) {
                    /*lookup_identity_debug1("[LIM] dbus call: %s", method);
                    lookup_identity_debug1("[LIM] dbus result: %s", ptr[i]); */

                    ngx_str_t *element;
                    element = ngx_array_push(output);
                    if (element == NULL) {
                        lookup_identity_log_error("Memory allocation failed.");
                        break;
                    }

                    data = ngx_palloc(r->pool, strlen(ptr[i]) * sizeof(u_char));
                    memcpy(data, ptr[i], strlen(ptr[i]) * sizeof(u_char));

                    element->data = data;
                    element->len = strlen(ptr[i]); 

                   /* lookup_identity_debug1("[LIM] Address start array: %d", output->elts);
                    lookup_identity_debug1("[LIM] Address of new element: %d", element);
                    lookup_identity_debug1("[LIM] Direct address of element data: %d", &element->data);
                    lookup_identity_debug2("[LIM] Address of element [%d] start in array: %d", i, &(((ngx_str_t *)output->elts)[i]));
                    lookup_identity_debug1("[LIM] Group list count: %d", output->nelts); 
                    lookup_identity_debug1("[LIM] Array element data: %s", ((ngx_str_t *)output->elts)[i].data);
                    */
                }
                dbus_free_string_array(ptr);
            }
            dbus_message_unref(reply);
        }

        if (dbus_error_is_set(&error)) {
            dbus_error_free(&error);
        }
        dbus_connection_unref(connection);
    }
    dbus_error_free(&error);

    return NGX_OK;
}

/*Do all the DBUS message related stuff*/
static DBusMessage * lookup_identity_dbus_message(ngx_http_request_t *r, DBusConnection * connection, DBusError * error, int timeout, const char * method, const char ** args) 
{
    DBusMessage * message = dbus_message_new_method_call(DBUS_SSSD_DEST, DBUS_SSSD_PATH, DBUS_SSSD_IFACE, method);
    if (! message) {
        lookup_identity_log_error("Error allocating dbus message");
        return NULL;
    }
    dbus_message_set_auto_start(message, TRUE);
        
    char * user = (char*) r->headers_in.user.data;
    lookup_identity_debug1("[LIM] dbus user: %s",user);
 
    int nargs = 0;
    
    if (args) {
        dbus_message_append_args(message, DBUS_TYPE_STRING, &user, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &args, nargs, DBUS_TYPE_INVALID);
    } 
    else {
        dbus_message_append_args(message, DBUS_TYPE_STRING, &user, DBUS_TYPE_INVALID);
    }

    DBusMessage * reply = dbus_connection_send_with_reply_and_block(connection, message, timeout, error);
        
    dbus_message_unref(message);

    if (dbus_error_is_set(error)) {
        lookup_identity_log_error("Lookup Identity: dbus error - method: %s",method);
        lookup_identity_log_error("Lookup Identity: dbus error - user: %s",user);
        lookup_identity_log_error("Lookup Identity: dbus error - errname: %s",error->name);
        lookup_identity_log_error("Lookup Identity: dbus error - errmessage: %s",error->message);
    } 
    else {
        int reply_type = DBUS_MESSAGE_TYPE_ERROR;
        reply_type = dbus_message_get_type(reply);
        
        if (reply_type == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
            return reply;
        }

        if (reply_type == DBUS_MESSAGE_TYPE_ERROR) {
            lookup_identity_log_error("Lookup Identity: dbus reply error");
            lookup_identity_log_error("Lookup Identity: dbus error - reply: %s",dbus_message_get_error_name(reply));
        }
        else {
            lookup_identity_log_error("Lookup Identity: Unexpected reply type");
            lookup_identity_log_error("Lookup Identity: dbus error - reply type: %s",reply_type);
        }
            
        lookup_identity_log_error("Lookup Identity: dbus error - method: %s",method);
        lookup_identity_log_error("Lookup Identity: dbus error - user: %s",user);
    }
    if(reply)
        dbus_message_unref(reply);
    return NULL; 
}
