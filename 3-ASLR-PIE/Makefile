make:
	gcc vuln.c -o vuln-1 -m32 -fno-stack-protector -no-pie
	gcc vuln.c -o vuln-2 -m32 -fno-stack-protector
	gcc vuln.c -o vuln-3 -m32 -fno-stack-protector -static
	gcc vuln.c -o vuln-4 -m32 -fno-stack-protector -static-pie
	
clean:
	rm -f vuln-1 vuln-2 vuln-3 vuln-4
