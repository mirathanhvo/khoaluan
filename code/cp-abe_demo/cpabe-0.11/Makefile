# Makefile dành cho cpabe-0.11

# Danh sách chương trình sẽ tạo
BIN_PROGRAMS = cpabe-setup cpabe-keygen cpabe-enc cpabe-dec

# Mỗi tool có file .c riêng, kèm file common.c.
# Thêm policy_lang.c vào nguồn của cpabe-enc vì hàm parse_policy_lang được sử dụng ở đó.
SETUP_SRC   = setup.c common.c
KEYGEN_SRC  = keygen.c common.c
ENC_SRC     = enc.c common.c policy_lang.c
DEC_SRC     = dec.c common.c

# Trình biên dịch & cờ
CC = gcc
CFLAGS = -O3 -Wall \
         $(shell pkg-config --cflags glib-2.0) \
         -I/usr/local/include/relic \
         -I../libbswabe-0.9 \
         -I. 

# Liên kết: tìm thư viện ở ../libbswabe-0.9 và /usr/local/lib
LDFLAGS = -L../libbswabe-0.9 -L/usr/local/lib -Wl,-rpath,../libbswabe-0.9 $(shell pkg-config --libs glib-2.0)

# Liên kết với các thư viện động: relic, bswabe, gmp, crypto, glib-2.0
LDADD = -lrelic -lbswabe -lgmp -lcrypto -lglib-2.0

all: $(BIN_PROGRAMS)

# cpabe-setup
cpabe-setup: $(SETUP_SRC:.c=.o)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDADD)

# cpabe-keygen
cpabe-keygen: $(KEYGEN_SRC:.c=.o)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDADD)

# cpabe-enc
cpabe-enc: $(ENC_SRC:.c=.o)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDADD)

# cpabe-dec
cpabe-dec: $(DEC_SRC:.c=.o)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDADD)

# Quy tắc biên dịch .c -> .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(BIN_PROGRAMS)

