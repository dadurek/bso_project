#include <pthread.h>

int val;

void *Thread1(void *x)
{
	val = 1;
	return x;
}

int main(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, Thread1, NULL);
    val = 2;
    pthread_join(thread, NULL);
    return val;
}
