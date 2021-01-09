#ifndef CMDOPT
#define CMDOPT

void cmdopt_parse(int argc, char *const argv[]);
void cmdopt_register(char option, char const *desc, int flag, int *flags, char const **arg);
void cmdopt_help(char const *cmd, int status);

#endif
