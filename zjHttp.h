/* #define ENABLE_FEATURE_WIN32 1 */

#define SERVER_STRING "Server:zjhttp/0.1.0\r\n"  /* server name */
#define BUF_SIZE 2048
#define HTTP_PORT 7749
#define CGI_ENVIRONMENT_SIZE 8192

#if ENABLE_FEATURE_WIN32
#define _ZJ_WIN32
#endif // ENABLE_FEATURE_WIN32


#ifdef _ZJ_WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#include <winsock2.h>
#pragma comment (lib, "ws2_32.lib")           /* 加载 ws2_32.dll */

typedef SOCKET Client;
typedef struct cgi_env {
	char buf[CGI_ENVIRONMENT_SIZE];       
	int len;                                
	int st;                               
} CGI_ENV;

#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
typedef int Client;

#endif  /* _ZJ_WIN32 */

#include <stdio.h>
#include <sys/stat.h>

void *accept_request(void*);
void bad_request(Client);
void cat(Client, FILE *);
void cannot_execute(Client);
void error_die(const char *);
void execute_cgi(Client, char *, const char *, const char *);
int get_line(Client, char *, int);
void headers(Client, const char *);
void not_found(Client);
void serve_file(Client, const char *);
int startup(int);
void unimplemented(Client);
