make:
	gcc vuln.c -o vuln-1.o -m32 -fno-stack-protector -no-pie
	gcc vuln.c -o vuln-2.o -m32 -fno-stack-protector
	gcc vuln.c -o vuln-3.o -m32 -fno-stack-protector -static
	gcc vuln.c -o vuln-4.o -m32 -fno-stack-protector -static-pie
	
clean:
	rm -f vuln-1.o vuln-2.o vuln-3.o vuln-4.o
