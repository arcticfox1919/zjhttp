#include <stdio.h>

int main(){
	printf("Content-Type: text/html\n");
	printf("\n");
    printf("<html>");
    printf("<head>");
    printf("<title>CGI</title>");
    printf("</head>");
    printf("<body>");
	printf("I am a CGI program!\n");
    printf("</body>");
    printf("</html>\n");
	
	return 0;
}