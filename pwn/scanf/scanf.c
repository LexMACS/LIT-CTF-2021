#include <stdio.h>
#include <stdlib.h>

char fmt[0x100];
char buf[0x100];

int main(){
	setbuf(stdout, 0x0);
	setbuf(stderr, 0x0);

	puts("Scanf is my favorite function, so here are it's lowest 3 address bytes (yay!):");
	printf("%p\n\n", (int)scanf & 0xffffff);

	puts("Now, you get to input any data type to buf with scanf! (yay!)\n");

	puts("The data types and corresponding inputs for each are as follow (yay!):");
	puts("String - \"%s\" (yay!)");
	puts("Character - \"%c\" (yay!)");
	puts("Integer - \"%d\" (yay!)");
	puts("Hex - \"%x\" (yay!)");
	puts("Decimal - \"%f\" (yay!)\n");

	puts("Input the kind of data type you want to input. (yay!)");

	scanf("%256s", fmt);
	getchar();

	puts("\nNow you get to input that data type! (yay!)");

	scanf(fmt, buf);
	getchar();

	puts("\nThat's all! (yay!)");

	return 0;
}
