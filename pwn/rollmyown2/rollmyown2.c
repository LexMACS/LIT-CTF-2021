#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <openssl/sha.h>

#include <unistd.h>
#include <seccomp.h>
#include <sys/types.h>

char *hash = (char *)0x420691337000;

int test0(){
	long x = 0;
	for(int i = 0; i < 0x10; i++){
		x += (long)hash[i] * 69420;
	}
	return x == 33391020;
}

int test1(){
	long x = 1;
	for(int i = 0; i < 0x10; i++){
		x *= ((long)hash[i] + 69420);
	}
	return x == 3360619469889077248;
}

int test2(){
	long x = 0;
	for(int i = 0; i < 0x10 / 4; i++){
		x ^= (long)((int *)hash)[i] << i;
	}
	return x == 15490497930;
}

const int (*tests[3])() = {test0, test1, test2};

void gethash(char buf[0x80]){
	srand(1337);

	char sha[0x14];

	for(int i = 0; i < 0x8; i++){
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, &buf[i * 0x10], 0x10);
		SHA1_Final(sha, &ctx);
		
		int x = rand() % 0x12;
		for(int j = 0; j < 2; j++) hash[2 * i + j] = sha[x + j];
	}

	puts("H4sh complete.\n");
}

int test(int x){
	if(x >= 3){
	 	puts("Index too large.");
	 	exit(0);
	}
	return tests[x]();
}

int main(){
	setbuf(stdout, 0x0);
	setbuf(stderr, 0x0);

	puts("Input the string you want to hash (max 128 chars).");

	char buf[0x80];
	memset(buf, 0x0, sizeof(buf));
	read(0x0, buf, 0x80);
	puts("");

	mmap((void *)hash, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0x0);
	gethash(buf);

	puts("What test index do you want to test your hash against (0-2)?");

	long x, t;
	t = scanf("%lld", &x);
	puts("");

	if(!t){
		puts("Index must be a number.");
		exit(0);	
	}

	if(x < 0){
	 	puts("Negative indices invalid.");
	 	exit(0);
	}

	printf("Testing against test %lld.\n\n", x);

	if(test(x)) puts("The string you hashed may be the flag.");
	else puts("The string you hashed is definitely not the flag.");

	return 0;
}
