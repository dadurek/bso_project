#include <stdio.h>
#include <string.h>

#define N 4

struct A
{
	char buf1 [N];
	char buf2 [N];
} a;

int main(int argc, char *argv[])
{
	strcpy(a.buf1, argv[1]);
	printf("buf1: %s", a.buf1);
	putchar('\n');
	printf("buf2: %s", a.buf2);
	return 0;
}
