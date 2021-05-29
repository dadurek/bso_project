#include <stdio.h>
#include <string.h>

#define N 8

struct A
{
	int x;
	int y;
};


int main(int argc, char *argv[])
{
	struct A a;
	memset(a.buf, 0, sizeof(a)+1);
	return 0;
}
