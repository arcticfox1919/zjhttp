#include "zjHttp.h"
#include <string.h>

#ifdef _ZJ_WIN32
#include <process.h>
#define CloseSocket(socket) closesocket((socket))
#define StrCaseCmp stricmp
#define CreateThreadEx(pthread,func,args) _beginthreadex(NULL, 0, ((unsigned int (__stdcall *)(void *))(func)), (args), 0, (pthread));
#define HandleThreadExcept(x) do{\
                                if ((x) == 0)\
                                    perror("pthread_create");\
                                    continue;\
                             }while (0)

#define CLEANUP() WSACleanup()

static int add_env(CGI_ENV *en,const char* key, const char *value) {
    if (en->st == 0) {
        sprintf(en->buf, "%s=%s", key, value);
        en->st = strlen(en->buf) + 1;
    }else {
        int offset = strlen(key) + strlen(value) + 1;
        if ((en->len - en->st) > offset) {
            sprintf((en->buf + en->st), "%s=%s", key, value);
            en->st += (offset + 1);
        }else return -1;
    }
    return en->st;
}

static void createCgiProcess(Client client, char *env, const char *path, const char *method ,int content_length) {
    DWORD byteRead, byteWrite;
    HANDLE readPipe1, writePipe1, readPipe2, writePipe2;
    SECURITY_ATTRIBUTES sat;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LARGE_INTEGER off;
    char buf[BUF_SIZE];
    char c;

    sat.nLength = sizeof(SECURITY_ATTRIBUTES);
    sat.bInheritHandle = TRUE;
    sat.lpSecurityDescriptor = NULL;

    /* 创建管道1 */
    if (!CreatePipe(&readPipe1, &writePipe1, &sat, NULL)) error_die("Create Pipe Error!\n");
    /* 设置子进程不继承管道1在父进程这一端的读取句柄 */
    if (!SetHandleInformation(readPipe1, HANDLE_FLAG_INHERIT, 0)) error_die("SetHandleInformation Error!\n");

    /* 创建管道2 */
    if (!CreatePipe(&readPipe2, &writePipe2, &sat, NULL)) error_die("Create Pipe Error!\n");
    /* 设置子进程不继承管道2在父进程这一端的写入句柄 */
    if (!SetHandleInformation(writePipe2, HANDLE_FLAG_INHERIT, 0)) error_die("SetHandleInformation Error!\n");

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    si.cb = sizeof(si);                    /* 包含STARTUPINFO结构的字节数，应为结构体的大小 */
    si.wShowWindow = SW_HIDE;              /* 设定子应用程序初次调用的ShowWindow时，应用程序的第一个重叠窗口应该如何出现 */
    si.dwFlags |= STARTF_USESTDHANDLES;    /* 包含该标志位，才能设置标准输入输出流 */
    si.hStdInput = readPipe2;              /* 将子进程的标准输入重定向到管道的读端 */
    si.hStdOutput = writePipe1;            /* 将子进程的标准输出重定向到管道的写端 */
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    if (!CreateProcess(NULL, path, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP,(LPVOID)env, NULL, &si, &pi))
        error_die("create process error!\n");

    if (StrCaseCmp(method, "POST") == 0){
        for (int i = 0; i < content_length; i++) {
            recv(client, &c, 1, 0);
            WriteFile(writePipe2, (LPCVOID)&c, 1, &byteWrite, NULL);     /* 将数据发送给cgi脚本 */
        }
    }

    int rSize = 1;
    int respLen = 0;
    char type[13];
    type[12] = '\0';
    char *p = NULL;
    memset(&buf, 0, sizeof(buf));
    while (rSize > 0 && ReadFile(readPipe1, buf, sizeof(buf), &byteRead, NULL)) {
        GetFileSizeEx(readPipe1, &off);
        rSize = (int)off.QuadPart;
        send(client, buf, strlen(buf), 0);
    }
    WaitForSingleObject(pi.hProcess,INFINITE);
    CloseHandle(readPipe1);
    CloseHandle(readPipe2);
    CloseHandle(writePipe1);
    CloseHandle(writePipe2);
}

#else
#define CloseSocket(socket) close((socket))
#define StrCaseCmp strcasecmp
#define CreateThreadEx(pthread,func,args) pthread_create((pthread), NULL,(func),(args))
#define HandleThreadExcept(x) do{\
                                if ((x) != 0)\
                                    perror("pthread_create");\
                                    continue;\
                             }while (0)
#define CLEANUP() 
typedef struct sockaddr SOCKADDR;
#define INVALID_SOCKET -1
#endif /* _ZJ_WIN32 */


int main() {
#ifdef _ZJ_WIN32
    SOCKET server_sock, client_sock;
    SOCKADDR clntAddr;
    int clntAddrLen = sizeof(SOCKADDR);
    unsigned newthread;
#else
    int server_sock = -1;
    int client_sock = -1;
    struct sockaddr_in clntAddr;
    socklen_t clntAddrLen = sizeof(clntAddr);
    pthread_t newthread;
#endif /* _ZJ_WIN32 */

    server_sock = startup(HTTP_PORT);
    printf(">>> zjhttp running on port %d <<<\n", HTTP_PORT);
    for (;;) {
        client_sock = accept(server_sock, (SOCKADDR*)&clntAddr, &clntAddrLen);
        if (client_sock == INVALID_SOCKET) {
            perror("accept");
            continue;
        }
        /* 启动线程处理收客户端请求 */
        int r = CreateThreadEx(&newthread, accept_request, (void *)client_sock);
        HandleThreadExcept(r);
    }
    CloseSocket(server_sock);
    CLEANUP();
    return 0;
}

/* 接收客户端的连接，读取请求数据 */
void *accept_request(void* args){
    Client client = (Client)args;
    char *method = NULL;
    char *url = NULL;
    char buf[BUF_SIZE];
    int numchars;
    char path[512];
    struct stat st;
    int cgi = 0;                 
    char *query_string = NULL;

    memset(buf, 0, sizeof(buf));
    /* 获取一行HTTP报文数据 */
    if ((numchars = get_line(client, buf, sizeof(buf))) == 0) return NULL;

    /* 获取Http请求行字段，格式为<method> <request-URL> <version> 每个字段以空白字符相连 */
    method = strtok(buf, " ");                                /* 从请求行中分割出method字段 */

    /* 本Demo仅实现GET请求和POST请求 */
    if (StrCaseCmp(method, "GET") && StrCaseCmp(method, "POST")){
        unimplemented(client);
        return NULL;
    }

    /* 如果请求方法为POST，cgi标志位置1,开启cgi解析 */
    if (StrCaseCmp(method, "POST") == 0) cgi = 1;

    url = strtok(NULL, " ");              /* 从请求行中分割出request-URL字段 */
    
    if (StrCaseCmp(method, "GET") == 0){  /* GET请求，url可能带有"?",有查询参数 */
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        if (*query_string == '?'){
            cgi = 1;                       /* 如果带有查询参数，执行cgi解析参数，设置标志位为1 */
            *query_string = '\0';          /* 将解析参数截取下来 */
            query_string++;
        }
    }

    /* url中的路径格式化到 path */
    sprintf(path, "static%s", url);

    /* 如果path只是一个目录，默认设置为首页 */
    if (path[strlen(path) - 1] == '/') strcat(path, "index.html");

    if (stat(path, &st) == -1) {     /* 访问的网页不存在，则读取剩下的请求头信息并丢弃 */
        while ((numchars > 0) && strcmp("\n", buf))  
            numchars = get_line(client, buf, sizeof(buf));
        not_found(client); 
    }else{
        /* 网页存在。路径如果是目录，显示主页 (S_IFDIR代表目录) */
        if ((st.st_mode & S_IFMT) == S_IFDIR) strcat(path, "/index.html");
#ifdef _ZJ_WIN32
        char *suffix = &path[strlen(path) - 4];
        if (StrCaseCmp(suffix, ".cgi") == 0) cgi = 1;
#else
        if ((st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH))
            cgi = 1;
#endif // _ZJ_WIN32
        if (!cgi) serve_file(client, path);                     /* 将静态文件返回 */
        else execute_cgi(client, path, method, query_string);   /* 执行cgi动态解析 */
    }
    CloseSocket(client);                                        /* 关闭套接字 */
    return NULL;
}

int startup(int port){
#ifdef _ZJ_WIN32
    WSADATA wsaData;                                            /* 初始化 DLL */
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET servSocket;
    SOCKADDR_IN  sockAddr;
#else
    int servSocket = 0;
    struct sockaddr_in sockAddr;
#endif /* _ZJ_WIN32 */
    /* 创建套接字 */
    if ((servSocket = socket(PF_INET, SOCK_STREAM, 0)) == -1) error_die("socket");

    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;                              /* 使用IPv4地址 */
    sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);               /* 不指定具体IP */
    sockAddr.sin_port = htons(port);                            /* 端口 */

    if (bind(servSocket, (SOCKADDR*)&sockAddr, sizeof(sockAddr)) < 0) error_die("bind");
    if (listen(servSocket, 10) < 0) error_die("listen");        /* 监听请求,最大的连接数10 */

    return servSocket;
}

void unimplemented(Client client){                              /* 501 相应方法未实现 */
    char buf[1024];
    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");  
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

void not_found(Client client){                                 /* 返回404 */
    char buf[1024];
    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

void cannot_execute(Client client){                            /* 发送500 */
    char buf[1024];
    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

void bad_request(Client client){                              /* 发送400 */
    char buf[1024];
    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}

void headers(Client client, const char *filename){            /* 发送HTTP头 */
    char buf[1024];
    (void)filename;            /* could use filename to determine file type */
    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}
 
/* 将请求的文件返回给浏览器客户端 */
void serve_file(Client client, const char *filename){
    FILE *resource = NULL;
    int numchars = 1;
    char buf[1024];
    buf[0] = 'A'; buf[1] = '\0';
    while ((numchars > 0) && strcmp("\n", buf))              /* 读取HTTP请求头并丢弃 */
        numchars = get_line(client, buf, sizeof(buf));

    resource = fopen(filename, "r");
    if (resource == NULL) not_found(client);
    else{
        headers(client, filename);                           /* 添加HTTP头 */
        cat(client, resource);                               /* 发送文件内容 */
    }
    fclose(resource);
}

/* 执行cgi动态解析 */
void execute_cgi(Client client, char *path, const char *method, const char *query_string) {
    char buf[1024];
    int numchars = 1;
    int content_length = -1;
    buf[0] = 'A'; buf[1] = '\0';
    if (StrCaseCmp(method, "GET") == 0) {                    /* 是GET请求,读取并丢弃头信息 */
        while ((numchars > 0) && strcmp("\n", buf))
            numchars = get_line(client, buf, sizeof(buf));
    }else {                                                 /* POST请求 */
        numchars = get_line(client, buf, sizeof(buf));
        while ((numchars > 0) && strcmp("\n", buf)) {       /* 循环读取头信息找到Content-Length字段值 */
            buf[15] = '\0';                                 /* 截取Content-Length: */

            if (StrCaseCmp(buf, "Content-Length:") == 0) content_length = atoi(&(buf[16]));/* 获取Content-Length的值 */
            numchars = get_line(client, buf, sizeof(buf));
        }
        if (content_length == -1) {
            bad_request(client);
            return;
        }
    }
    sprintf(buf, "HTTP/1.0 200 OK\r\n");                    /* 返回正确响应码200 */
    send(client, buf, strlen(buf), 0);
#ifdef _ZJ_WIN32
    CGI_ENV env;
    memset(&env, 0, sizeof(env));
    env.len = sizeof(env.buf);
    add_env(&env, "SYSTEMROOT", getenv("SYSTEMROOT"));
    add_env(&env, "REQUEST_METHOD", method);

    if (StrCaseCmp(method, "GET") == 0) {
        add_env(&env, "QUERY_STRING", query_string);
    }else {                        /* POST */
        add_env(&env, "CONTENT_LENGTH", content_length);
    }
    char abspath[MAX_PATH];
    GetModuleFileName(NULL, abspath, MAX_PATH);

    char *p = NULL;
    for (p = abspath + strlen(abspath); *p != '\\'; p--);
    *(++p) = '\0';

    for (p = path; *p != '\0'; p++) {
        if (*p == '/') *p = '\\';
    }

    strcat(abspath, path);
    printf("abspath=%s\n", abspath);
    createCgiProcess(client, env.buf, abspath, method, content_length);
#else
    int cgi_output[2];
    int cgi_input[2];
    pid_t pid;
    int status,i;
    char c;

    /* 必须在fork()中调用pipe()，否则子进程不会继承文件描述符
       pipe(cgi_output)执行成功后，cgi_output[0]为读通道 cgi_output[1]为写通道 */
    if (pipe(cgi_output) < 0) {
        cannot_execute(client);
        return;
    }
    if (pipe(cgi_input) < 0) {
        cannot_execute(client);
        return;
    }

    if ((pid = fork()) < 0) {
        cannot_execute(client);
        return;
    }
    /* fork出一个子进程运行cgi脚本 */
    if (pid == 0)  /* 子进程 */{
        char meth_env[255];
        char query_env[255];
        char length_env[255];

        dup2(cgi_output[1], 1);                            /* 1代表着stdout，0代表着stdin，将系统标准输出重定向为cgi_output[1] */
        dup2(cgi_input[0], 0);                             /* 将系统标准输入重定向为cgi_input[0] */

        close(cgi_output[0]);                              /* 关闭了cgi_output中的读通道 */
        close(cgi_input[1]);                               /* 关闭了cgi_input中的写通道 */
                            
                            
        sprintf(meth_env, "REQUEST_METHOD=%s", method);    /* CGI标准需要将请求的方法存储环境变量存储REQUEST_METHOD */
        putenv(meth_env);
        if (strcasecmp(method, "GET") == 0) {
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }else {   /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }

        execl(path, path, NULL);                           /* 执行CGI脚本 */
        exit(0);
    }else {    /* 父进程 */
        close(cgi_output[1]);                              /* 关闭了cgi_output中的写通道，此处是父进程中cgi_output变量*/
        close(cgi_input[0]);                               /* 关闭了cgi_input中的读通道 */
        if (strcasecmp(method, "POST") == 0)
            for (i = 0; i < content_length; i++) {
                recv(client, &c, 1, 0);                    /* 开始读取POST中的内容*/
                write(cgi_input[1], &c, 1);                /* 将数据发送给cgi脚本 */
            }
        
        while (read(cgi_output[0], &c, 1) > 0)             /* 读取cgi脚本返回数据 */
            send(client, &c, 1, 0);

        close(cgi_output[0]);
        close(cgi_input[1]);
        waitpid(pid, &status, 0);
    }
#endif /* _ZJ_WIN32 */
}

void cat(Client client, FILE *resource){
    char buf[1024];
    fgets(buf, sizeof(buf), resource);                      /* 读取文件到buf中 */
    while (!feof(resource)){                                /* 判断文件是否读取到末尾 */
        send(client, buf, strlen(buf), 0);                  /* 读取并发送文件内容 */
        fgets(buf, sizeof(buf), resource);
    }
}

void error_die(const char *sc){
    perror(sc);
    exit(1);
}

int get_line(Client client, char *buf, int size){
    int i = 0;
    char c = '\0';
    while ((i < size - 1) && (c != '\n')){
        if (recv(client, &c, 1, 0) > 0) {
            if (c == '\r') {
                if ((recv(client, &c, 1, MSG_PEEK) > 0) && (c == '\n'))
                    recv(client, &c, 1, 0);
                else c = '\n';
            }
            buf[i] = c;
            i++;
        }else c = '\n';
    }
    buf[i] = '\0';
    return(i);
}
