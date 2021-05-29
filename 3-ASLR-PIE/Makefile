CC = gcc
CFLAGS = -m32 -fno-stack-protector

make:
	${CC} vuln.c -o vuln-1.o ${CFLAGS} -no-pie
	${CC} vuln.c -o vuln-2.o ${CFLAGS}
	${CC} vuln.c -o vuln-3.o ${CFLAGS} -static
	${CC} vuln.c -o vuln-4.o ${CFLAGS} -static-pie
	
clean:
	rm -f vuln-1.o vuln-2.o vuln-3.o vuln-4.o
