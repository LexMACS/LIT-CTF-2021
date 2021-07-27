#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

struct review{
	struct review *fd, *bk;
	long stars;
	char *description;
};

struct product{
	char *name;
	long price, instock, model, reviewnum;
	struct review *hd;
};

const char leettime[] = "Tue Jul 20 13:37:42 2021";
struct product *shop[0x20];

void initsecurity(){	
	#define ArchField offsetof(struct seccomp_data, arch)

	#define Allow(syscall) \
    	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
   	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

	struct sock_filter filter[] = {
   		/* validate arch */
   		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
    		BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    		/* load syscall */
    		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    		/* list of allowed syscalls */
		Allow(brk),         /* used by malloc */
		Allow(mmap),        /* used by malloc */
    		Allow(exit_group),  /* exits a processs */
    		Allow(write),       /* called by printf */
    		Allow(fstat),       /* called by printf */
		Allow(read),	    /* called by scanf */
		Allow(open),        /* called by open */
		Allow(openat),      /* called by time */
		Allow(lseek),       /* called by time */
		Allow(close),       /* called by time */
		Allow(stat),        /* called by time */

    		/* and if we don't match above, die */
    		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

	puts("S3cur1ty complete.\n");
}

int menu(){
	puts("You have the options of:");
	puts("1) Add product");
	puts("2) Add review");
	puts("3) Remove review");
	puts("4) Show product");
	puts("5) Create knockoff");
	puts("6) Get time");
	puts("7) Exit\n");

	puts("What would you like to do?");

	int x;
	scanf("%d", &x);
	puts("");

	return x;	
}

int getidx(){
	int idx = 0;
	while(idx < 0x20 && shop[idx]) idx++;
	if(idx == 0x20){
		puts("Out of space.");
		_exit(1);
	}
	return idx;
}

int inidx(){
	int idx;
	scanf("%d", &idx);
	if(idx < 0 || idx >= 0x20 || !shop[idx]){
		puts("Invalid index.");
		_exit(1);
	}
	puts("");
	return idx;
}

int inlen(){
	int len;
	scanf("%d", &len);
	if(len <= 0 || len > 0x1000){
		puts("Invalid length.");
		_exit(1);
	}
	return len;
}

void addproduct(){
	puts("Great, you can now add a product!\n");

	int idx = getidx();
	shop[idx] = malloc(sizeof(struct product)); 

	printf("The new product will have index %d.\n\n", idx);

	puts("How long do you want the product name to be?");

	int len = inlen() + 1;
	shop[idx]->name = malloc(len);

	puts("Now input the name.");

	shop[idx]->name[read(0x0, shop[idx]->name, len) - 1] = '\0';

	puts("\nNow enter the product price.");
	
	scanf("%lld", &shop[idx]->price);

	puts("\nNow enter the number of products in stock.");

	scanf("%lld", &shop[idx]->instock);

	puts("\nNow enter the product model number.");

	scanf("%lld", &shop[idx]->model);

	shop[idx]->reviewnum = 0;
	shop[idx]->hd = malloc(sizeof(struct review));
	shop[idx]->hd->fd = shop[idx]->hd->bk = 0;

	puts("\nIt looks like you're good to go!\n");
}

void addreview(){
	puts("Great, now you get to add a review!\n");

	puts("Input which product index you want to add a review for.");

	int idx = inidx();

	struct review *ptr = shop[idx]->hd;

	for(int i = 0; i < shop[idx]->reviewnum; i++) ptr = ptr->fd;

	ptr->fd = malloc(sizeof(struct review));
	ptr->fd->bk = ptr;
	ptr = ptr->fd;
	ptr->fd = 0;

	puts("Now input the number of stars you want to give in the review.");

	scanf("%lld", &ptr->stars);

	puts("\nNow, how long do you want the review description to be?");

	int len = inlen() + 1;
	ptr->description = malloc(len);

	puts("Ok, now enter the description.");

	ptr->description[read(0x0, ptr->description, len) - 1] = '\0';

	shop[idx]->reviewnum++;

	puts("\nNice, you successfully added the review!\n");
}

void removereview(){
	puts("Alright, you can now remove a review!\n");

	puts("Input the product index you want to remove a review for.");

	int idx = inidx();

	puts("Ok, what review index do you want to remove?");

	int ridx;
	scanf("%d", &ridx);

	if(ridx < 0 || ridx >= shop[idx]->reviewnum){
		puts("Invalid review index.");
		_exit(1);
	}

	struct review *ptr = shop[idx]->hd;

	for(int i = 0; i <= ridx; i++) ptr = ptr->fd;

	struct review *fd = ptr->fd, *bk = ptr->bk;
	if(fd) fd->bk = bk;
       	if(bk) bk->fd = fd;

	free(ptr->description);
	free(ptr);

	shop[idx]->reviewnum--;

	puts("\nIt seems the review was removed successfully!\n");
}

void showproduct(){
	puts("It's definitely great to see the products sometimes!\n");

	puts("Which product do you want to see?");

	int idx = inidx();

	printf("Alright, listing all product information for product %d:\n\n", idx);

	printf("Name: %s\n", shop[idx]->name);
	printf("Price: %d\n", shop[idx]->price);
	printf("In stock: %d\n", shop[idx]->instock);
	printf("Model number: %d\n", shop[idx]->model);
	printf("Number of reviews: %d\n\n", shop[idx]->reviewnum);

	puts("Alright, now listing all of the reviews:\n");

	struct review *ptr = shop[idx]->hd;
	for(int i = 0; i < shop[idx]->reviewnum; i++){
		ptr = ptr->fd;
		printf("----Review %d----\n", i);
		printf("Stars: %d\n", ptr->stars);
		printf("Description: %s\n\n", ptr->description);
	}

	puts("Ok, I think that's all the info!\n");
}

void addknockoff(){
	puts("Alright, time to create a knockoff product!\n");

	puts("Which product do you want to base it off of?");

	int idx = inidx(), idy = getidx();

	printf("Ok, the new product based on index %d will have a new index %d.\n\n", idx, idy);

	shop[idy] = malloc(sizeof(struct product));

	memcpy(shop[idy], shop[idx], sizeof(struct product));
	
	shop[idy]->price /= 2, shop[idy]->instock *= 2;
	shop[idy]->name = strdup(shop[idx]->name);

	for(int i = 0; i < strlen(shop[idy]->name); i++){
		if(rand() & 1) shop[idy]->name[i] = toupper(shop[idy]->name[i]);
		else shop[idy]->name[i] = tolower(shop[idy]->name[i]);
	}

	shop[idy]->hd = malloc(sizeof(struct review));

	struct review *ptrx = shop[idx]->hd, *ptry = shop[idy]->hd;

	memcpy(ptry, ptrx, sizeof(struct review));

	for(int i = 0; i < shop[idx]->reviewnum; i++){
		ptry->fd = malloc(sizeof(struct review));
		ptrx = ptrx->fd, ptry = ptry->fd;
		memcpy(ptry, ptrx, sizeof(struct review));
		ptry->stars -= 2;
		ptry->description = strdup(ptrx->description);
	}

	printf("New product %s complete!\n\n", shop[idy]->name);
}

void gettime(int w, int x, int y, int z){
	time_t curtimer = time(0);
	char *curtime = ctime(&curtimer);
	
	printf("The current time is %s\n", curtime);

	if(!strncmp(curtime, leettime, strlen(leettime))){
		FILE *f = fopen("flag.txt", "r");
		if(f == NULL){
			puts("Something went wrong. Please contact Rythm.");
			exit(1);
		}
		char flag[0x80];
		fgets(flag, 0x78, f);

		if(w != 0x13376969 || x != 0xdeadbeef || y != 0xcafebabe || z != 0xb01dface){
			puts("Wtmoo, you almost got me!");
			puts("I may like to write cheap tricks but I don't like when you write them! :angry:");
			_exit(1);
		}

		puts("Huh, you must be a l33t h4ck3r because you made it just in time!");
		puts("Since the ctf is over, here's the flag:");
		puts(flag);
		puts("");
	}else{
		puts("It ain't leet time yet.");
		puts("You can see the flag after the ctf is over if you join at leet time.");
		printf("Leet time is %s\n\n", leettime);
	}
}

int main(){
	setbuf(stdout, 0x0);
	setbuf(stderr, 0x0);
	srand(time(0));	
	
	puts("Yay, you decided to try my problem!");
	puts("Do you think you can finess through my cheap tricks?\n");

	initsecurity();

	puts("I created a nice interface for you to manage my new e-commerce website: Gondwana!");
	puts("You can add products, reviews, and more!\n");

	while(1){
		int x = menu();
		switch(x){
			case 1:
				addproduct();
				break;
			case 2:
				addreview();
				break;
			case 3:
				removereview();
				break;
			case 4:
				showproduct();
				break;
			case 5:
				addknockoff();
				break;
			case 6:
				gettime(0x13376969, 0xdeadbeef, 0xcafebabe, 0xb01dface);
				break;
			case 7:
				puts("Perhaps you're too poor to pull off even a cheap trick. :pensive:");
				break;
			default:
				puts("Invalid option.");
				_exit(1);
				break;
		}
		if(x == 7) break;
	}
		
	return 0;
}
