#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	if ( (host = gethostbyname(hostname)) == NULL )
	{
		printf("Eroor: %s\n",hostname);
		perror(hostname);
		abort();
	}

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);

	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(sd);
		perror(hostname);
		abort();
	}

	return sd;
}

SSL_CTX* InitCTX(void)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = SSLv23_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */

	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
//		printf("Error: %s\n",stderr);
		printf("Error on InitCTX !!!\n" );
		abort();
	}

	return ctx;
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */

	if ( cert != NULL )
	{
		printf("=========================================================================\n");
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);   /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		printf("=========================================================================\n");
		free(line);   /* free the malloc'ed string */
		X509_free(cert); /* free the malloc'ed certificate copy */
	}
	else
		printf("No certificates.\n");
}


int ReadFromSSL(SSL* ssl)
{
	char c = '\0';
	
	while( SSL_read(ssl, &c, 1) > 0 ) 
	{
		printf("%c",c) ;
	}
	
	return 0;
}


int main(int count, char *strings[])
{
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	//char buf[1024];
	//int bytes;
	char *hostname, *portnum;

	if ( count != 3 )
	{
		printf("usage: %s <hostname> <portnum>\n", strings[0]);
		exit(0);
	}
	SSL_library_init();
	hostname = strings[1];
	portnum = strings[2];

	ctx = InitCTX();
	server = OpenConnection( hostname, atoi(portnum) );
	ssl = SSL_new(ctx);  /* create new SSL connection state */
	SSL_set_fd(ssl, server);/* attach the socket descriptor */

	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
	{
		//printf("Eroor: %s\n",stderr);
		printf("Error on SSL_connect !!!\n");
		ERR_print_errors_fp(stderr);
	}
	else
	{
		char *msg = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36\r\nAccept-Encoding: deflate,sdch\r\nAccept-Language: zh-CN,zh;q=0.8,en;q=0.6,ja;q=0.4\r\n\r\n";
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);/* get any certs */
		SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
		printf("Receive: ================================================================\n");
		/*
		bzero( buf , sizeof(buf) ) ;
		bytes = SSL_read(ssl, buf, sizeof(buf)) ; 
		while( bytes > 0 ) 
		{
			buf[bytes] = '\0' ;
			printf("%s", buf);
			if( buf[0]=='0' && buf[1] == '\0' ) break ;
			bzero( buf , sizeof(buf) ) ;
			bytes = SSL_read(ssl, buf, sizeof(buf)) ; 
		}
		*/
		ReadFromSSL(ssl);
		printf("=========================================================================\n");
		SSL_free(ssl);/* release connection state */
	}

	close(server); /* close socket */
	SSL_CTX_free(ctx);/* release context */

	return 0;
}
