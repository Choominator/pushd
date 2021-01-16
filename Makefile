export FILESYSTEMNAME=pushd
export PRETTYNAME=Push Notifications Daemon

CC?=cc

CFLAGS?=-DNDEBUG -O3
LDFLAGS?=-Xlinker -strip-all

LIBS=
OBJS=main.o cmdopt.o event.o hashset.o
HEADERS=config.h cmdopt.h event.h hashset.h

build: $(FILESYSTEMNAME)

clean:
	rm -f $(OBJS) config.h $(FILESYSTEMNAME)

$(FILESYSTEMNAME): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) -o $(FILESYSTEMNAME) $^

$(OBJS): %.o: %.c $(HEADERS)
	$(CC) -D_POSIX_C_SOURCE=200809L $(CFLAGS) -c -o $@ $<

config.h: Makefile
	echo "#ifndef CONFIG" > config.h
	echo "#define CONFIG" >> config.h
	for macro in FILESYSTEMNAME PRETTYNAME; do echo "#define CONFIG_`echo $$macro | sed 's/\(NAME$$\)/_\1/'` \"`eval echo \\$$$$macro`\"" >> config.h; done
	echo "#endif" >> config.h
