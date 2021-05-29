#include <stdio.h>
#include <string.h>

#define N 8

struct A
{
	struct B
	{
		char buf[N];
	} b;
	char buf[N];
} a;


int main(int argc, char *argv[])
{
	strcpy(&a.b.buf[1], "deadbead");
	return 0;
}
