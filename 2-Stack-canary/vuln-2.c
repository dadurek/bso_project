#include <stdio.h>
#include <string.h>

void vuln()
{
	char buffer[600];
	gets(buffer);
	printf(buffer);
	printf("\n");
	gets(buffer);
}

int main(int argc, char *argv[])
{
	vuln();
	return 0;
}
