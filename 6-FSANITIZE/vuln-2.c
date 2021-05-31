#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 18

int main(void)
{
	const char buf1 [] = "Test of sanitizers";
	char buf2 [N];
	strcpy(buf2, buf1);
	return EXIT_SUCCESS;
}
