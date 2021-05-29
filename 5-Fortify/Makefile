CC = gcc
CFLAGS1 = -m32 -O1 -D_FORTIFY_SOURCE=1
CFLAGS2 = -m32 -O1 -D_FORTIFY_SOURCE=2

make:
	${CC} vuln-1.c -o vuln-1.o ${CFLAGS2} 
	${CC} vuln-2.c -o vuln-2.o ${CFLAGS2}
	${CC} vuln-3.c -o vuln-3.o ${CFLAGS2}
	${CC} vuln-4.c -o vuln-4-1.o ${CFLAGS1}
	${CC} vuln-4.c -o vuln-4-2.o ${CFLAGS2}

clean:
	rm -f vuln-1.o vuln-2.o vuln-3.o vuln-4-1.o vuln-4-2.o
