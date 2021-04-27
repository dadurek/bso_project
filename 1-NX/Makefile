make:
	gcc vuln.c -o vuln -m32 -z execstack -fno-stack-protector -no-pie
	gcc vuln.c -o vuln-protected -m32 -fno-stack-protector -no-pie

clean: 
	rm -f vuln vuln-protected
