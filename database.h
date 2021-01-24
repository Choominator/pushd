#ifndef DATABASE
#define DATABASE

void database_cmdopt(void);
void database_init(void);
int database_insert_group_device(char const *group, size_t group_len, char const *device, size_t device_len);
int database_select_group_devices(char const *group, size_t group_len);
int database_next_device(char const **device, size_t *device_len);
int database_delete_device(char const *device, size_t device_len);

#endif
