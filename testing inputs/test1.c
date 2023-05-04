#include <stdio.h>
#include <stdlib.h>

int randomRange(int min, int max) {
	return (rand() % (max - min)) + min;
}

int main() {
	int w = 3;
	int flag;
	if (w <= 2) {
		flag = 1;
	} else {
		flag = 0;
	}
	int x = 2;
	int y;
	if (x == 2) {
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
