CC1 = gcc
CC2 = clang
BASE = -m32 -g
LEAK = -fsanitize=leak
ADDRESS = -fsanitize=address
MEMORY = -fsanitize=memory
THREAD = -fsanitize=thread 
UNDEFINED = -fsanitize=undefined
WARNINGS = -Wall -Wextra 

make:
	${CC1} vuln-1.c -o vuln-1.o ${BASE} ${ADDRESS}
	${CC1} vuln-2.c -o vuln-2-1.o ${BASE} ${ADDRESS}
	${CC1} vuln-2.c -o vuln-2-2.o ${BASE} ${ADDRESS} ${WARNINGS} 
	${CC1} vuln-3.c -o vuln-3-1.o ${BASE} ${WARNINGS}
	${CC2} vuln-3.c -o vuln-3-2.o ${MEMORY} 
	${CC1} vuln-4.c -o vuln-4.o ${THREAD}
	${CC1} vuln-5.c -o vuln-5.o ${UNDEFINED}
	${CC1} vuln-6.c -o vuln-6.o ${UNDEFINED} 

clean:
	rm -f *.o
