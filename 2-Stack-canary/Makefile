CC = gcc
CFLAGS = -m32 -z execstack

make:
	${CC} vuln-1.c -o vuln-1.o ${CFLAGS} -fno-stack-protector -no-pie 
	${CC} vuln-1.c -o vuln-2.o ${CFLAGS} -fstack-protector -no-pie
	${CC} vuln-2.c -o vuln-3.o ${CFLAGS} -fstack-protector

clean:
	rm -f vuln-1.o vuln-1.o vuln-2.o
