#include <switch.h>
#include <time.h>

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_fail2ban_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_fail2ban_load);

/* SWITCH_MODULE_DEFINITION(name, load, shutdown, runtime) 
 * Defines a switch_loadable_module_function_table_t and a static const char[] modname
 */
SWITCH_MODULE_DEFINITION(mod_fail2ban, mod_fail2ban_load, mod_fail2ban_shutdown, NULL);

switch_memory_pool_t *modpool;
char *logfile_name = "/var/log/freeswitch/fail2ban.log";
switch_file_t *logfile;
switch_event_types_t event = SWITCH_EVENT_CUSTOM;
const char *subclass_name = SWITCH_EVENT_SUBCLASS_ANY;

static switch_status_t mod_fail2ban_do_config(void);

static void fail2ban_event_handler(switch_event_t *event)
{
	time_t rawtime;
	struct tm * timeinfo;
	char buffer [25];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

        if (event->event_id == SWITCH_EVENT_CUSTOM && strncmp(event->subclass_name, "sofia::register_attempt",23) == 0) {
                strftime (buffer,25,"%FT%T%z",timeinfo);
                switch_file_printf(logfile, "%s", buffer);
                switch_file_printf(logfile, " A registration was attempted ");
                switch_file_printf(logfile, "%s:%s ", "User", switch_event_get_header(event, "to-user"));
                switch_file_printf(logfile, "%s:%s", "IP", switch_event_get_header(event, "network-ip"));
                switch_file_printf(logfile, "\n");
        } else if (event->event_id == SWITCH_EVENT_CUSTOM && strncmp(event->subclass_name, "sofia::register_failure",23) == 0) {
                strftime (buffer,25,"%FT%T%z",timeinfo);
                switch_file_printf(logfile, "%s", buffer);
                switch_file_printf(logfile, " A registration failed ");
                switch_file_printf(logfile, "%s:%s ", "User", switch_event_get_header(event, "to-user"));
                switch_file_printf(logfile, "%s:%s", "IP", switch_event_get_header(event, "network-ip"));
                switch_file_printf(logfile, "\n");
        } else if (strncmp(event->subclass_name, "sofia::pre_register",19) == 0) {
                strftime (buffer,25,"%FT%T%z",timeinfo);
                switch_file_printf(logfile, "%s", buffer);
                switch_file_printf(logfile, " A preregistration was attempted ");
                switch_file_printf(logfile, "%s:%s ", "User", switch_event_get_header(event, "to-user"));
                switch_file_printf(logfile, "%s:%s", "IP", switch_event_get_header(event, "network-ip"));
                switch_file_printf(logfile, "\n");
        }

}

// SWITCH_DECLARE(int) switch_file_printf(switch_file_t *thefile, const char *format, ...);

/* Macro expands to: switch_status_t mod_fail2ban_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_fail2ban_load)
{
	void *user_data = NULL;
	switch_status_t status;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	modpool = pool;

	if ((status = switch_event_bind(modname, event, subclass_name, fail2ban_event_handler, user_data)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event bind failed\n");
		return SWITCH_STATUS_FALSE;
	} 
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event bind success\n");

	if (mod_fail2ban_do_config() != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_FALSE;
	}

	switch_file_printf(logfile, "Fail2ban was started\n");
	
	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_fail2ban_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_fail2ban_shutdown)
{
	switch_status_t status;

	switch_file_printf(logfile, "Fail2ban stopping\n");
	if ((status = switch_event_unbind_callback(fail2ban_event_handler)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event bind failed\n");
		return status;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "event bind removed\n");

	if ((status = switch_file_close(logfile)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "failed to close %s\n", logfile_name);		
		return status;
	} 
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "successfully closed %s\n", logfile_name);
	
	return status;
}

static switch_status_t mod_fail2ban_do_config(void)
{
	switch_status_t status;
	char *cf = "fail2ban.conf";
	switch_xml_t cfg, xml, bindings_tag, config = NULL, param = NULL;
	char *bname;
	char *var;
	char *val;
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "setting configs\n");		

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}
	
	if (!(bindings_tag = switch_xml_child(cfg, "bindings"))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing <bindings> tag!\n");
		goto done;
	}
	
	for (config = switch_xml_child(bindings_tag, "config"); config; config = config->next) {
		bname = (char *) switch_xml_attr_soft(config, "name");
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "bname: %s\n",bname);		
		
		for (param = switch_xml_child(config, "param"); param; param = param->next) {
			var = (char *) switch_xml_attr_soft(param, "name");
			val = (char *) switch_xml_attr_soft(param, "value");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "%s: %s\n", var, val);		
			
			if (strncmp(var,"logfile", 7) == 0) {
				logfile_name = val;
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unknown attribute %s: %s\n", var, val);		
			}
		}	
	}
	
		
	if ((status = switch_file_open(&logfile, logfile_name, SWITCH_FOPEN_WRITE|SWITCH_FOPEN_APPEND|SWITCH_FOPEN_CREATE, SWITCH_FPROT_OS_DEFAULT, modpool)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "failed to open %s\n", logfile_name);		
		return SWITCH_STATUS_FALSE;
	} 

 done:
	switch_xml_free(xml);
	
	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4
 */
