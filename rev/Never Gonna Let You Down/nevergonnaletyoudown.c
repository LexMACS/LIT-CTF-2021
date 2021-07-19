#include <stdio.h>
#include <stdlib.h>

unsigned char encode(int param1,unsigned char param2,unsigned char param3) {
	return ((((param3) >> param1) & 1) | (0xfe & (param2)));
}

int main() {
	unsigned char flag[50];
	FILE* flag_file = fopen("flag.txt","r");
	if(flag_file == (FILE *)0x0) {
		puts("Error: The flag file does not exist");
		exit(0);
	}
	if(fread(flag,50,1,flag_file) < 1) {
		puts("Error: The flag is too short");
		exit(0);
	}

	FILE* original_file = fopen("yougotrickrolled.bmp","r");
	FILE* output_files[3];
	output_files[0] = fopen("yougotrickrolled1.bmp","a");
	output_files[1] = fopen("yougotrickrolled2.bmp","a");
	output_files[2] = fopen("yougotrickrolled3.bmp","a");
	for(int i = 0;i < 4800;++i) {
		unsigned char b;
		fread(&b,1,1,original_file);
		fputc(b,output_files[0]);
		fputc(b,output_files[1]);
		fputc(b,output_files[2]);
	}
	time_t t;
	srand((unsigned) time(&t));
	for(int i = 0;i < 50;++i) {
		for(int j = 0;j < 8;++j) {
			unsigned char b;
			fread(&b,1,1,original_file);
			unsigned char special_c = encode(j,b,(flag[i] ^ 0x68));
			int cur = rand() % 3;
			if(cur % 3 == 0) {
				fputc(special_c,output_files[0]);
				fputc(b,output_files[1]);
				fputc(b,output_files[2]);
			}else if(cur % 3 == 1) {
				fputc(special_c,output_files[1]);
				fputc(b,output_files[0]);
				fputc(b,output_files[2]);
			}else{
				fputc(special_c,output_files[2]);
				fputc(b,output_files[0]);
				fputc(b,output_files[1]);
			}
		}
	}
	unsigned char b;
	int working = fread(&b,1,1,original_file);
	while(working == 1) {
		fputc(b,output_files[0]);
		fputc(b,output_files[1]);
		fputc(b,output_files[2]);
		working = fread(&b,1,1,original_file);
	}
	fclose(flag_file);
	fclose(original_file);
	fclose(output_files[0]);
	fclose(output_files[1]);
	fclose(output_files[2]);
	return 0;
}

