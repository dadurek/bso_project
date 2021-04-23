make:
	gcc vuln.c -o vuln -m32 -z execstack -fno-stack-protector
	gcc vuln.c -o vuln-protected -m32 -fno-stack-protector

clean: 
	rm -f vuln vuln-protected
