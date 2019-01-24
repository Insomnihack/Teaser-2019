#pragma once

#undef UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <synchapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <winbase.h>
#include <processthreadsapi.h>

#pragma comment (lib, "Ws2_32.lib")
// for WaitOnAddress / WakeOnAddressAll
#pragma comment (lib, "synchronization.lib")

#define MAX_HEADERS_LENGTH 0x2000
#define SOCKET_TIMEOUT     (60 * 1000)
#define MAX_THREADS        5

typedef struct {
	char *key;
	char *value;
} dictionary_entry, *dictionary;

typedef struct {
	SOCKET sockfd;
	HANDLE heap;
	char method[16];
	char filename[256];
	char *query_string;
	char protocol[16];
	char hostname[128];
	dictionary headers;
	size_t headers_count;
	dictionary params; /* GET & POST params */
	size_t params_count;
	char *content; /* POST content*/
	size_t content_length;
} http_request;

typedef struct {
	char *name;
	int(*func)(http_request *);
} endpoint;

#define DOCTYPE             "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">"

#define ERROR_400           "Bad Request"
#define ERROR_401           "Unauthorized"
#define ERROR_403           "Access forbidden"
#define ERROR_404           "Not Found"
#define ERROR_413           "Request Entity Too Large"
#define ERROR_500           "Internal Server Error"
#define ERROR_501           "Not Implemented"
#define ERROR_505           "HTTP Version Not Supported"


#define return_error400_if(sockfd, condition) \
	do { if (condition) { return error400(sockfd); } } while (0);

#define exit_error400_if(sockfd, condition) \
	do { if (condition) { error400(sockfd); exit(1); } } while (0);

#define send_error_header(client, error_code) \
	send_response_headers(client, #error_code " " ERROR_##error_code);

#define send_error_body(client, error_code, error_msg)                           \
	send_response_body(client, DOCTYPE "\n"                                      \
	                   "<title>" #error_code " " ERROR_##error_code "</title>\n" \
	                   "<h1>" ERROR_##error_code "</h1>\n"                       \
	                   error_msg);

void setsock_timeout(SOCKET sockfd);
char *strcpy_n(char *dest, char *src, size_t n);
int sendlen(SOCKET sockfd, const char *buf, size_t n);
int sendstr(SOCKET sockfd, const char *str);
int recvlen(SOCKET sockfd, char *buf, int n, char *stop);
size_t urldecode(char *dst, const char *src);

char *dict_get(dictionary dict, size_t dict_size, const char *key, int case_sensitive);
void dict_add(http_request *req, dictionary *dict, size_t *counter,
              char *key, char *value, size_t value_size);

int page_login(http_request *req);
