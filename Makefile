all : HttpsServer HttpsClient

HttpsServer.o : HttpsServer.c HttpsServer.h
	gcc -g -W -Wall -c HttpsServer.c -o HttpsServer.o 

ReadConfFile.o : ReadConfFile.c ReadConfFile.h
	gcc -g -W -Wall -c ReadConfFile.c -o ReadConfFile.o
	
MD5.o: MD5.c MD5.h
	gcc -g -W -Wall -c MD5.c -o MD5.o

HttpsServer : ReadConfFile.o MD5.o HttpsServer.o 
	gcc -g -W -Wall -o HttpsServer HttpsServer.o ReadConfFile.o MD5.o -lpthread -lssl

HttpsClient: HttpsClient.c 
	gcc -g -W -Wall -o HttpsClient HttpsClient.c -lssl



.PHONY:clean
clean :
	rm -f HttpsServer HttpsClient *.o
rebuild : clean all
