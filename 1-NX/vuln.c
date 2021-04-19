//gcc vuln.c -o vuln -m32 -fno-stack-protector -no-pie -z execstack

#include <stdio.h>
#include <string.h>

void vuln(){
	char buffer[16];
	gets(buffer);
	printf("Buffer = %p", buffer);
}

int main(int argc, char *argv[])
{
	vuln();
}
