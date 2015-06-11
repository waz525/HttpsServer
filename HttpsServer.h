#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <sys/wait.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL -1


#ifdef linux
#include <ctype.h>
#endif

#include "ReadConfFile.h"
#include "MD5.h"

#define SERVER_VERSION "HttpServer/1.2"
#ifdef linux
#define BUFFER_SIZE 1460
#else
#define BUFFER_SIZE 1448
#endif

char DOCUMENT_ROOT[512] ;
int SERVER_PORT ;
int DEBUG_MODE ;
char LOG_FILE_PATH[256] ;

char CERT_FILE_PATH[256] ;
char KEY_FILE_PATH[256] ;
SSL_CTX *ctx;

char HTTP_HOST[100] , HTTP_CACHE_CONTROL[100], HTTP_ACCEPT_ENCODING[100], HTTP_USER_AGENT[1000] , HTTP_ORIGIN[256] , HTTP_CONNECTION[100] , HTTP_ACCEPT_LANGUAGE[100] , HTTP_REFERER[1000] , HTTP_ACCEPT[200] , CONTENT_LENGTH[100] , CONTENT_TYPE[200] , HTTP_COOKIE[1000] , HTTP_RANGE[100] , HTTP_IFRANGE[100] ;
	

void writelogstring(char * str) ;
void SendNotFound(SSL* ssl) ;
void SendUnimplementedMethod(SSL* ssl) ;
void SendBadRequest(SSL* ssl) ; 
void SendMovedPermanently(SSL* ssl , char * newUrl) ;
long SendHtmlContent(SSL* ssl, char * path ) ;

void GetMethodUrl( char * buffer , char * method , char * requestUrl ) ;
void GetContentTypeByExName( char * path , char * ContentType) ;
void GetPara(char * buffer , char * dest , int start  );
void DelRepeatedChar( char * buffer , char c );
int Hex2Int(char * hex );
void DealPath(char * path );
int isFileExist(char * filePath);


void execCgiBin(SSL* ssl , char * FullPath , char * REQUEST_METHOD , char *  QUERY_STRING );
void DealWithClient(int *client) ;
void server() ;

#endif

