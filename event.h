#ifndef EVENT
#define EVENT

typedef struct event event_t;
typedef void (*event_handler_t)(event_t *event, siginfo_t *info, void *data);

void event_loop(void);
event_t *event_subscribe(int signum, event_handler_t handler, void *data);
void event_retain(event_t *event);
void event_release(event_t *event);

#endif
