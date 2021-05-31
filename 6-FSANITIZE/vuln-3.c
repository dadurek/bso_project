#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void set_val(bool *b, int val)
{
		if(val == 1){
			*b = false;
		}
}

int main(void)
{		
		bool b; 
		int val;
		scanf("%d", &val);
		set_val(&b, val);
		if (b) {
			puts("Value set");
		}
		return EXIT_SUCCESS;
}
