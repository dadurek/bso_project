CC = gcc
CFLAGS = -m32 -no-pie

make:
	${CC} vuln.c -o vuln-1.o ${CFLAGS} -Wl,-z,norelro
	${CC} vuln.c -o vuln-2.o ${CFLAGS}
	${CC} vuln.c -o vuln-3.o ${CFLAGS} -z relro -z now

clean:
	rm -f *.o
