CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

GCC=gcc
BIN=example
SRC=example.c
OBJ=example.o ../common/conn.o ../common/http.o ../common/setting.o ../common/net.o cert.o

CFLAGS=-I${HOME}/boringssl/include
LDFLAGS=-L${HOME}/boringssl/build/crypto -L${HOME}/boringssl/build/ssl -lssl -lcrypto -ldl -lpthread

all: example

example: ${OBJ}
	${CC} -o ${BIN} ${OBJ} ${LDFLAGS}

example.o: ${SRC}
	${CC} ${FLAGS} ${CFLAGS} -c $<

clean:
	rm ${BIN} ${OBJ}
