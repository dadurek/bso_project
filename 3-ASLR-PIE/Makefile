make:
	gcc vuln.c -o vuln-1 -m32 -fno-stack-protector -no-pie
	gcc vuln.c -o vuln-protected-2 -m32 -fno-stack-protector
	gcc vuln.c -o vuln-protected-3 -m32 -fno-stack-protector -static
clean:
	rm -f vuln-1 vuln-protected-2
