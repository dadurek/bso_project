CC = gcc
CFLAGS = -m32 -fno-stack-protector

make:
	${CC} vuln.c -o vuln-1.o -m32 ${CFLAGS} -no-pie
	${CC} vuln.c -o vuln-2.o -m32 ${CFLAGS}
	${CC} vuln.c -o vuln-3.o -m32 ${CFLAGS} -static
	${CC} vuln.c -o vuln-4.o -m32 ${CFLAGS} -static-pie
	
clean:
	rm -f vuln-1.o vuln-2.o vuln-3.o vuln-4.o
