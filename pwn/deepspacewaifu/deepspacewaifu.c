#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char *names[0x5] = {"Sarah", "Mitsumi", "Tomoko", "Ayame", "Nekotine"};
int numadd = 7, numfre = 1337, numrd = 3, numchg = 2;
long isfre[0x7], state[0x7];
char *waifu[0x7];

int menu(){
        puts("You have the options of:");
        puts("1) Create waifu");
        puts("2) Launch waifu");
        puts("3) Modify waifu");
        puts("4) Display waifu");
        puts("5) Leave waifus\n");

        puts("What would you like to do?");

        int x;
        scanf("%d", &x);
        puts("");

        return x;
}

void createwaifu(){
        printf("You have %d create waifu calls left (creating waifus is risky so it is limited for security).\n\n", numadd);

        if(!numadd){
                puts("Smh no more creating waifus for you.\n");
                return;
        }

        puts("How much data do you want to configure your waifu with?");

        long len;
        scanf("%ld", &len);
        puts("");

        int x = 0;
        while(x < 0x7 && waifu[x]) x++;

        if(x < 0x7){
                waifu[x] = malloc(len);
                strcpy(waifu[x], names[rand() % 5]);
                printf("This waifu is tagged with id %d and name %s.\n", x, waifu[x]);
                puts("Sounds like it'll be a top tier waifu!\n");
                for(int i = 0; i < 0x7; i++){
                        if(i != x && waifu[i] == waifu[x]){
                                isfre[i] = state[i] = 0;
                                waifu[i] = 0;
                        }
                }
                numadd--;
        }else{
                puts("Waifu could not be created.\n");
        }
}

void launchwaifu(){
        printf("You have %d launch waifu calls left (we want to make sure you can launch to deep space a lot).\n\n", numfre);

        if(!numfre){
                puts("Smh no more launching waifus into space for you.\n");
                return;
        }

        puts("Which waifu would you like to launch into deep space?");

        int x;
        scanf("%d", &x);
        puts("");

        if(x >= 0 && x < 0x7 && waifu[x] && !isfre[x]){
                puts("It sounds like the waifu space journey of a dream.\n");
                free(waifu[x]);
                isfre[x] = 1, state[x] = *((long *)waifu[x]);
                numfre--;
        }else{
                puts("Bruh put a valid index.\n");
        }
}

void modifywaifu(){
        printf("You have %d modify waifu calls left (modifying waifus is risky so it is limited for security).\n\n", numchg);

        if(!numchg){
                puts("Smh no more editing waifus for you.\n");
                return;
        }

        puts("Thanks to large leaps in human modification, you now have the ability to modify waifus!");
        puts("Which waifu do you want to modify?");

        int x;
        scanf("%d", &x);
        puts("");

        if(x >= 0 && x < 0x7 && waifu[x] && !isfre[x]){
                puts("Nice, now you can input the waifu data you'd like to change.");
                puts("Note: you can't modify the first 0x10 bytes of a waifu bcz that can cause dramatic personality changes!");
                waifu[x][0x10 + read(0x0, waifu[x] + 0x10, malloc_usable_size(waifu[x]) - 0x10)] = 'Q';
                puts("");
                numchg--;
        }else{
                puts("Bruh put a valid index.\n");
        }

}

void displaywaifu(){
        printf("You have %d display waifu calls left (you are limited in seeing waifus for some contrived reason).\n\n", numrd);

        if(!numrd){
                puts("Smh no more displaying waifus for you.\n");
                return;
        }

        puts("What waifu do you want to display?");

        int x;
        scanf(" %d", &x);
        puts("");

        if(x >= 0 && x < 0x7 && waifu[x] && !isfre[x]){
                puts("Nice, here's the waifu you wished to see:");
                puts("Note: the first 0x10 bytes are not read because that can leak top secret waifu personality data!");
                write(0x1, waifu[x] + 0x10, malloc_usable_size(waifu[x]) - 0x10);
                puts("");
                numrd--;
        }else{
                puts("Bruh put a valid index.\n");
        }
}

void leavewaifus(){
        puts("You're leaving your waifus already? They will miss you! :sob:\n");

        puts("Before you leave, you can modify a waifu one last time.");
        puts("Would you like to do so? (Y/n)");

        char c;
        scanf(" %c", &c);
        puts("");

        if(c == 'Y' || c == 'y'){
                puts("Nice, always good to take every chance you got!\n");
                numchg = 1;
                modifywaifu();
        }else{
                puts("Alright, best not to get carried away I guess.\n");
        }

        puts("Your waifus say goodbye!");
        exit(0);
}

void waifusecurity(){
        for(int i = 0; i < 0x7; i++){
                if(isfre[i] && state[i] != *((long *)waifu[i])){
                        puts("Uh oh, it seems your waifus are starting to combine data! :eyes:");
                        puts("This may be a sci-fi waifu game, but you're going beyond the range of ethical waifu mods!");
                        exit(1);
                }
        }
}


int main(){
        setbuf(stdout, 0x0);
        setbuf(stderr, 0x0);
        srand(time(0));

        puts("Welcome to my deepspacewaifu creator game!");
        puts("I hope you're excited to get to create waifus to your heart's desire!");
        puts("Well actually, human modification is dangerous, so we have some waifu restrictions and security in place.");
        puts("Maybe it won't be to your hearts desire, but hopefully you enjoy your waifu creations anyway!\n");

        while(1){
                int x = menu();
                switch(x){
                        case 1:
                                createwaifu();
                                break;
                        case 2:
                                launchwaifu();
                                break;
                        case 3:
                                modifywaifu();
                                break;
                        case 4:
                                displaywaifu();
                                break;
                        case 5:
                                leavewaifus();
                                break;
                        default:
                                puts("Invalid option.\n");
                                break;
                }
                waifusecurity();
        }

        return 0;
}
