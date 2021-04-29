make:
	gcc vuln.c -o vuln-1 -m32 -z execstack -fno-stack-protector -no-pie
	gcc vuln.c -o vuln-2 -m32 -fno-stack-protector -no-pie

clean: 
	rm -f vuln-1 vuln-2
