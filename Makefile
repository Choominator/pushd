export FILESYSTEMNAME=pushd
export PRETTYNAME=Push Notifications Daemon

CC?=cc

CFLAGS?=-DNDEBUG -O3
LDFLAGS?=-Xlinker -strip-all

LIBS=
OBJS=main.o cmdopt.o
HEADERS=config.h cmdopt.h

build: $(FILESYSTEMNAME)

clean:
	rm -f $(OBJS) config.h $(FILESYSTEMNAME)

$(FILESYSTEMNAME): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) -o $(FILESYSTEMNAME) $^

$(OBJS): %.o: %.c $(HEADERS)
	$(CC) -D_POSIX_SOURCE $(CFLAGS) -c -o $@ $<

config.h: Makefile
	echo -e "#ifndef CONFIG\n#define CONFIG\n" > config.h
	for macro in FILESYSTEMNAME PRETTYNAME; do echo "#define CONFIG_`echo $$macro | sed 's/\(NAME$$\)/_\1/'` \"`eval echo \\$$$$macro`\"" >> config.h; done
	echo -e "\n#endif" >> config.h