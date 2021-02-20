#ifndef DATABASE
#define DATABASE

void database_cmdopt(void);
void database_init(void);
int database_subscribe(char const *device, size_t device_len, char const *group, size_t group_len);
int database_query_reset(void);
int database_query_add_group(char const *group, size_t group_len);
int database_query_step(char const **device, size_t *device_len);
void database_query_abort(void);
int database_device_del(char const *device, size_t device_len);

#endif
