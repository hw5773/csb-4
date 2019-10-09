CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

GCC=gcc
CLIENT=client
CLIENT_SRC=client.c rsa.c cert.c
CLIENT_OBJ=client.o ../common/conn.o ../common/http.o ../common/setting.o ../common/net.o rsa.o cert.o

BINS=${CLIENT}
OBJS=${CLIENT_OBJ}

TARGET_DIR=/usr/local/bin

CFLAGS=-I${HOME}/boringssl/include
LDFLAGS=-L${HOME}/boringssl/build/crypto -L${HOME}/boringssl/build/ssl -lssl -lcrypto -ldl -lpthread

HOST=www.bob.com
PORT=5555

all: client

client: ${CLIENT_OBJ}
	${CC} -o ${CLIENT} ${CLIENT_OBJ} ${LDFLAGS}

client.o: ${CLIENT_SRC}
	${CC} ${FLAGS} ${CFLAGS} -c $<

install: ${BINS}
	sudo cp ${BINS} ${TARGET_DIR}

uninstall: ${BINS}
	sudo rm ${TARGET_DIR}/${BINS}

clean:
	rm ${BINS} ${OBJS}
