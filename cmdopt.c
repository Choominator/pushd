#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include "cmdopt.h"

struct cmdopt_spec {
    char option;
    char const *desc;
    int flag;
    int *flags;
    char const *deflt;
    char const **arg;
    size_t count;
};

static struct cmdopt_spec *cmdopt_specs = NULL;
static char cmdopt_switches[128] = ":";
static char * cmdopt_switches_tail = cmdopt_switches + 1;

static size_t cmdopt_index(char option);

void cmdopt_parse(int argc, char *const argv[]) {
    if (!cmdopt_specs) return;
    opterr = 0;
    size_t errors = 0;
    for (;;) {
        int option = getopt(argc, argv, cmdopt_switches);
        if (option == '?') {
            fprintf(stderr, "%s: Invalid option: -%c\n", argv[0], optopt);
            ++ errors;
        } else if (option == ':') {
            fprintf(stderr, "%s: Option requires an argument: -%c\n", argv[0], optopt);
            ++ errors;
        } else if (option < 0) break;
        size_t index = cmdopt_index(option);
        if (cmdopt_specs[index].count ++) {
            fprintf(stderr, "%s: Option specified too many times: -%c\n", argv[0], option);
            ++ errors;
            continue;
        }
        if (cmdopt_specs[index].flags) *cmdopt_specs[index].flags |= cmdopt_specs[index].flag;
        if (cmdopt_specs[index].arg) *cmdopt_specs[index].arg = optarg;
    }
    for (; optind < argc; ++ optind) {
        fprintf(stderr, "%s: Unexpected argument: %s\n", argv[0], argv[optind]);
        ++ errors;
    }
    if (errors) cmdopt_help(argv[0], EXIT_FAILURE);
    free(cmdopt_specs);
}

void cmdopt_register(char option, char const *desc, int flag, int *flags, char const **arg) {
    if (!cmdopt_specs) {
        cmdopt_specs = calloc(62, sizeof *cmdopt_specs);
        if (!cmdopt_specs) {
            fprintf(stderr, "Unable to allocate memory for command line options\n");
            exit(EXIT_FAILURE);
        }
    }
    size_t index = cmdopt_index(option);
    assert(!cmdopt_specs[index].desc);
    cmdopt_specs[index] = (struct cmdopt_spec) {
        .option = option,
        .desc = desc,
        .flag = flag,
        .flags = flags,
        .deflt = arg ? *arg : NULL,
        .arg = arg
    };
    *(cmdopt_switches_tail ++) = option;
    if (cmdopt_specs[index].deflt) *(cmdopt_switches_tail ++) = ':';
    *cmdopt_switches_tail = 0;
}

void cmdopt_help(char const *cmd, int status) {
    printf("Usage: %s", cmd);
    for (char *option = cmdopt_switches + 1; *option; ++ option) {
        if (*option == ':') continue;
        size_t index = cmdopt_index(*option);
        if (cmdopt_specs[index].deflt) printf(" [-%c ARG]", *option);
        else printf(" [-%c]", *option);
    }
    printf("\n");
    for (char *option  = cmdopt_switches + 1; *option; ++ option) {
        if (*option == ':') continue;
        size_t index = cmdopt_index(*option);
        if (cmdopt_specs[index].deflt) printf("  -%c\t%s [%s]\n", cmdopt_specs[index].option, cmdopt_specs[index].desc, cmdopt_specs[index].deflt);
        else printf("  -%c\t%s\n", cmdopt_specs[index].option, cmdopt_specs[index].desc);
    }
    exit(status);
}

static size_t cmdopt_index(char option) {
    if (option < 'A') abort();
    if (option - 'A' <= 'Z' - 'A') return option - 'A';
    if (option < 'a') abort();
    if (option - 'a' <= 'z' - 'a') return option - 'a' + 26;
    if (option < '0') abort();
    if (option - '0' <= '9' - '0') return option - '0' + 52;
    abort();
    return 62;
}
