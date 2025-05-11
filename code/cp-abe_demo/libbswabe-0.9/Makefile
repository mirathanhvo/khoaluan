top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib
includedir = ${prefix}/include

CC = gcc
CFLAGS  = -O3 -Wall \
    $(shell pkg-config --cflags glib-2.0) \
    $(shell pkg-config --cflags gmp) \
    $(shell pkg-config --cflags openssl) \
    $(shell pkg-config --cflags relic) \
    -I/usr/local/include/relic \
    -I. \
    -I/home/thanh/Documents/cp-abe_demo/cpabe-0.11 \
    -DPACKAGE_NAME="libbswabe" -DPACKAGE_TARNAME="libbswabe" -DPACKAGE_VERSION="0.9" \
    -DHAVE_LIBCRYPTO=1 -DHAVE_STRDUP=1 -DHAVE_GMP=1 -DHAVE_BSWABE=1

LDFLAGS = -O3 -Wall \
    $(shell pkg-config --libs glib-2.0) \
    $(shell pkg-config --libs gmp) \
    $(shell pkg-config --libs openssl) \
    $(shell pkg-config --libs relic) \
    -L/usr/local/lib

DISTNAME = libbswabe-0.9

all: libbswabe.a libbswabe.so

# Tạo thư viện tĩnh
libbswabe.a: core.o misc.o bswabe.o
	rm -f $@
	ar rc $@ $^
	ranlib $@

# Tạo thư viện động
libbswabe.so: core.o misc.o bswabe.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Biên dịch từng file .c thành file .o
%.o: %.c *.h Makefile
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

# Cài đặt thư viện và header
install: libbswabe.a libbswabe.so bswabe.h
	mkdir -p $(DESTDIR)$(libdir)
	mkdir -p $(DESTDIR)$(includedir)
	cp libbswabe.a $(DESTDIR)$(libdir)/
	cp libbswabe.so $(DESTDIR)$(libdir)/
	cp bswabe.h $(DESTDIR)$(includedir)/

# Gỡ cài đặt
uninstall:
	rm -f $(DESTDIR)$(libdir)/libbswabe.a
	rm -f $(DESTDIR)$(libdir)/libbswabe.so
	rm -f $(DESTDIR)$(includedir)/bswabe.h

# Dọn dẹp file tạm
clean:
	rm -rf *.o *.a *.so TAGS *~

# Dọn dẹp hoàn toàn
distclean: clean
	rm -rf autom4te.cache Makefile config.status config.log config.cache configure

