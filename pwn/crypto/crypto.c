#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/mman.h>

char user_buf[0x130];

char* pick_symbol_with_AI(){
	char *ret = malloc(0x9);

	for(int i = 0; i < 4; i++){
		char x = rand();
		ret[i] = x + (x / 0x1a) * -0x1a + 'A';
	}

	ret[4] = 'c';
	ret[5] = 'o';
	ret[6] = 'i';
	ret[7] = 'n';
	ret[8] = '\0';

	return ret;
}

void init_blockchain(){
	puts("Crypto is secure due to a record of transactions maintained across computers.");
	puts("This mechanism is known as the blockchain, and is the backbone of crypto.");
	puts("Before buying crypto, please add your transaction record to the block chain.\n");

	long blockchain_loc;
	puts("Input the blockchain location.");
	scanf("%p", &blockchain_loc);
	getchar();
	
	if(mprotect(blockchain_loc ^ (blockchain_loc & 0xfff), 0x1000, PROT_READ | PROT_WRITE) == -1){
		puts("Blockchain could not be secured.");
		exit(1);
	}
	
	puts("Initialized blockchain security.\n");

	puts("Input 1 byte transaction code.");
	scanf("%c", blockchain_loc);

	puts("Transaction has been recorded to blockchain.\n");
}

void buy_crypto(){
	puts("Buying crypto...");

	char *crypto_types[0x41];
	for(int i = 0; i < 8; i++){
		crypto_types[i] = pick_symbol_with_AI();	
	}

	puts("What crypto do you want to see?");

	int index;
	scanf("%d", &index);

	char **ptr = &crypto_types[index];
	puts(*ptr);
	puts("");

	init_blockchain();
	
	puts("What is your API token?");
	getchar();

	index = read(0x0, user_buf, 0x12c);
	user_buf[index] = '\0';

	for(int i = 0; i < 0x12c; i++){
		switch(user_buf[i]){
			case 0x41:
    			case 0x45:
    			case 0x46:
    			case 0x47:
    			case 0x58:
    			case 0x61:
    			case 0x64:
    			case 0x65:
   			case 0x66:
    			case 0x67:
    			case 0x69:
    			case 0x6f:
    			case 0x70:
    			case 0x73:
    			case 0x75:
    			case 0x78:
				puts("Hey! Only one leak allowed!");
				exit(1);
			case 0x6e:
				puts("Notified by our friends at wallstreet, printf writes are insecure!");
				exit(1);
		}
	}

	puts("Buying crypto with token:");
	printf(user_buf);

	puts("Completed crypto trade.\n");
}

int main(){
	setbuf(stdout, 0x0);
	setbuf(stderr, 0x0);
	srand(time(0));

	puts("Welcome back to the trading app!\n");
	puts("What would you like to do?");
	puts("1) Buy some crypto!");

	int choice;
	scanf("%d", &choice);

	puts("");

	if(choice == 1){
		buy_crypto();
	}

	return 0;
}
