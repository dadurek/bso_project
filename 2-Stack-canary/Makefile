make:
	gcc vuln.c -o vuln -m32 -z execstack -fno-stack-protectr
	gcc vuln-protected-1.c -o vuln-protected-1 -m32 -z execstack -fstack-protector
	gcc vuln-protected-2.c -o vuln-protected-2 -m32 -z execstack -fstack-protector

clean:
	rm -f vuln vuln-protected-1 vuln-protected-2
