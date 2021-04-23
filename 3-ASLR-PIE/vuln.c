#include <stdio.h>
#include <stdlib.h>


void win(){
	system("/bin/sh");
}

void vuln()
{
	char buffer[16];
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
