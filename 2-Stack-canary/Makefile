make:
	gcc vuln-1.c -o vuln-1.o -m32 -z execstack -fno-stack-protector -no-pie 
	gcc vuln-1.c -o vuln-2.o -m32 -z execstack -fstack-protector -no-pie
	gcc vuln-2.c -o vuln-3.o -m32 -z execstack -fstack-protector

clean:
	rm -f vuln-1.o vuln-1.o vuln-2.o
