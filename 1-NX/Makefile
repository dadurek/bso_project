CC = gcc
CFLAGS = -m32 -fno-stack-protector -no-pie

make:
	${CC} vuln.c -o vuln-1.o ${CFLAGS} -z execstack  
	${CC} vuln.c -o vuln-2.o ${CFLAGS}
clean: 
	rm -f vuln-1.o vuln-2.o
