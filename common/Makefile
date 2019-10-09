CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

GCC=gcc
OBJS=conn.o http.o setting.o net.o
SRCS=conn.c http.c setting.c net.c
CFLAGS=-I${HOME}/boringssl/include

all: ${OBJS}

.c.o: ${SRCS}
	${GCC} -c $< ${CFLAGS}

clean:
	rm ${OBJS}
