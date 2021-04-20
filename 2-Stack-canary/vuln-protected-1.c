//gcc vuln-protected-1.c -o vuln-protected-1 -m32 -fstack-protector -z execstack

#include <stdio.h>
#include <string.h>

void vuln()
{
	char buffer[16];
	gets(buffer);
	printf("Buffer = %p", buffer);
}

int main(int argc, char *argv[])
{
	vuln();
	return 0;
}
