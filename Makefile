export FILESYSTEMNAME=pushd
export PRETTYNAME=Push Notifications Daemon

CC?=cc

CFLAGS?=-DNDEBUG -O3
LDFLAGS?=-Xlinker -strip-all

export BROKERADDR?=localhost:7874
export DATABASEPATH?=pushd.db
export CERTPATH=pushd.crt
export KEYPATH=pushd.key

LIBS=-levent -lyajl -lssl -lcrypto -lnghttp2 -lsqlite3
OBJS=main.o cmdopt.o broker.o request.o dispatch.o channel.o notification.o database.o
HEADERS=config.h cmdopt.h broker.h request.h dispatch.h channel.h notification.h database.h

build: $(FILESYSTEMNAME)

clean:
	rm -f $(OBJS) config.h $(FILESYSTEMNAME)

$(FILESYSTEMNAME): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) -o $(FILESYSTEMNAME) $^

$(OBJS): %.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -D_POSIX_C_SOURCE=200809L -c -o $@ $<

config.h: Makefile
	@echo "#ifndef CONFIG" > config.h
	@echo "#define CONFIG" >> config.h
	@for macro in FILESYSTEMNAME PRETTYNAME BROKERADDR DATABASEPATH CERTPATH KEYPATH; do echo "#define CONFIG_`echo $$macro | sed 's/\(NAME$$\|ADDR$$\|PATH$$\)/_\1/'` \"`eval echo \\$$$$macro`\"" >> config.h; done
	@echo "#endif" >> config.h
