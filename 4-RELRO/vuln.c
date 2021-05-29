#include <stdio.h>
#include <string.h>

void vuln()
{
	char buffer[512];
	gets(buffer);
	printf(buffer);
	scanf("%s",buffer);
	puts(buffer);
}

int main(int argc, char *argv[])
{
	vuln();
	return 0;
}
