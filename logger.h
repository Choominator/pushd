#ifndef LOGGER
#define LOGGER

void logger_cmdopt(void);
void logger_init(struct event_base *base, int foreground);
void logger_propagate(char const *format, ...);
void logger_fail(char const *format, ...);
void logger_complain(char const *format, ...);
void logger_report(char const *format, ...);
void logger_debug(char const *format, ...);

#endif
