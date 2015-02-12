#include <stdio.h>
#include <ctm/dumpcode.h>
void fn1() {
	printf("First\n");
}
void fn2() {
	printf("Second\n");
}
void fn3() {
	printf("Third\n");
}
void inputfn(int n) {
	printf("The number is %d\n", n);
}
int main(int argc, char* argv[]) {
	
	char buf[4];
	fgets(buf, 100, stdin);
	dumpcode(buf, 100);
	return 0;
}
