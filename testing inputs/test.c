#include <stdio.h>
#include <stdlib.h>

int randomRange(int min, int max) {
	return (rand() % (max - min)) + min;
}

int main() {
	int i;
	for (i = 0; i < 30; i ++) {
		printf("interation %d\n", i);
		int test1 = randomRange(0, 2);
		printf("test1: %d\n", test1);
		int test2 = randomRange(0, 2);
		printf("test2: %d\n", test2);
		int flag;
		if (test1 >= 0.5) {
			flag = 1;
		} else {
			flag = 0;
		}
		int x = 2;
		int y;
		if (test2 >= 0.5) {
			y = 4;
		} else {
			y = 5;
		}
		int z;
		if (flag) {
			z = y + x;
		} else {
			z = x + 1;
		}
		printf("%d\n", z);
	}
	return 0;
}
