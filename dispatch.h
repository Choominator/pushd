#ifndef DISPATCH
#define DISPATCH

void dispatch_cmdopt(void);
void dispatch_init(struct event_base *base);
void dispatch_enqueue(notification_queue_t *queue);

#endif
