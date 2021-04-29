make:
	gcc vuln-1.c -o vuln-1 -m32 -z execstack -fno-stack-protector 
	gcc vuln-1.c -o vuln-2 -m32 -z execstack -fstack-protector
	gcc vuln-2.c -o vuln-3 -m32 -z execstack -fstack-protector

clean:
	rm -f vuln-1 vuln-1 vuln-2
