make:
	gcc vuln.c -o vuln-1.o -m32 -z execstack -fno-stack-protector -no-pie
	gcc vuln.c -o vuln-2.o -m32 -fno-stack-protector -no-pie

clean: 
	rm -f vuln-1.o vuln-2.o
