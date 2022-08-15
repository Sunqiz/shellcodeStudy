#include "stdio.h"
#include "windows.h"
#include "stdlib.h"
#include "string.h"
#define PASSWORD "1234567"
int verify_password(char *password)
{
	int authenticated;
	char buffer[44];
	authenticated = strcmp(password,PASSWORD);
	strcpy(buffer,password);
	return authenticated;
}
int main(int argc, char* argv[])
{
	int valid_flag = 0;
	char password[5010];
	FILE * fp;
	if(!(fp = fopen("password.txt","rw+")))
	{
		exit(0);
	}
	fgets(password, 500, (FILE*)fp);
	//fscanf(fp,"%s",password);
	for(int i=0;i<=325;i++)
	{
		printf("%x",*(password+i)&0xff);
	}
	//valid_flag = verify_password(password);
	if(valid_flag)
	{
		printf("No!\n");
	}
	else
	{
		printf("Yes\n");
	}
	fclose(fp);
	getchar();
	return 0;
}

