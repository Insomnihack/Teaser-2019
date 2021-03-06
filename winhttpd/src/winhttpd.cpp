#include "stdafx.h"
#include "winhttpd.h"

static const endpoint endpoints[] = {
	{"login", page_login}
};
static char webroot[4096];

CRITICAL_SECTION CriticalSection;
int ThreadCount = 0;

static void send_response_headers(SOCKET sockfd, const char *status)
{
	sendstr(sockfd, "HTTP/1.1 ");
	sendstr(sockfd, status);
	sendstr(sockfd, "\r\n");
	sendstr(sockfd, "Server: winhttpd 0.1337");
	sendstr(sockfd, "\r\nConnection: close\r\n");
}

static void send_response_body(SOCKET sockfd, const char *body)
{
	char buf[100];
	size_t len;

	len = strlen(body);
	sprintf_s(buf, sizeof(buf) - 1, "Content-Length: %zu\r\n", len);

	sendstr(sockfd, buf);
	sendstr(sockfd, "Content-Type: text/html; charset=UTF-8\r\n\r\n");
	sendlen(sockfd, body, len);
}

static int error400(SOCKET sockfd)
{
	send_error_header(sockfd, 400);
	send_error_body(sockfd, 400, "<p>Your browser (or proxy) sent a request that this server could not understand.");

	return 400;
}

static int error403(SOCKET sockfd)
{
	send_error_header(sockfd, 403);
	send_error_body(sockfd, 403, "<p>You don't have permission to access the requested directory.</p>"
	                "<p>There is either no index document or the directory is read-protected.</p>");

	return 404;
}

static int error404(SOCKET sockfd)
{
	send_error_header(sockfd, 404);
	send_error_body(sockfd, 404, "<p>The requested URL was not found on the server.</p>"
	                "<p>If you entered the URL manually please check your spelling and try again.</p>");

	return 404;
}

static int error413(SOCKET sockfd)
{
	send_error_header(sockfd, 413);
	send_error_body(sockfd, 413, "<p>The request is larger than the server is willing or able to process</p>");

	return 413;
}

static int error500(SOCKET sockfd)
{
	send_error_header(sockfd, 500);
	send_error_body(sockfd, 500, "<p>The server encountered an internal error and was unable to complete your "
	                "request. Either the server is overloaded or there was an error in a CGI script.</p>");

	return 500;
}

static int error501(SOCKET sockfd)
{
	send_error_header(sockfd, 501);
	send_error_body(sockfd, 501, "<p>The server does not support the action requested by the browser.</p>");

	return 501;
}

static int error505(SOCKET sockfd)
{
	send_error_header(sockfd, 505);
	send_error_body(sockfd, 505, "<p>The server does not support the HTTP version required by the browser.</p>");

	return 505;
}

static void content_type(SOCKET sockfd, char *filename)
{
	char *content_type;
	const char *extension;
	char buf[200];

	for (extension = filename + strlen(filename) - 1;
	     extension > filename && *extension != '.';
	     extension--);

	if (!strcmp(extension, ".html") || !strcmp(extension, ".htm")) {
		content_type = "text/html";
	} else if (!strcmp(extension, ".css")) {
		content_type = "text/css; charset=utf-8";
	} else if (!strcmp(extension, ".jpeg") || !strcmp(extension, ".jpg")) {
		content_type = "image/jpeg";
	} else if (!strcmp(extension, ".png")) {
		content_type = "image/png";
	} else if (!strcmp(extension, ".gif")) {
		content_type = "image/gif";
	} else if (!strcmp(extension, ".pdf")) {
		content_type = "application/pdf";
	} else if (!strcmp(extension, ".mpeg") || !strcmp(extension, ".mp2") ||
	           !strcmp(extension, ".mp3")) {
		content_type = "video/mpeg";
	} else if (!strcmp(extension, ".js")) {
		content_type = "application/x-javascript";
	} else if (!strcmp(extension, ".tar")) {
		content_type = "application/x-tar";
	} else if (!strcmp(extension, ".zip")) {
		content_type = "application/zip";
	} else if (!strcmp(extension, ".gz") || !strcmp(extension, ".tgz")) {
		content_type = "application/x-compressed";
	} else {
		content_type = "text/plain";
	}

	sprintf_s(buf, sizeof(buf) - 1, "Content-Type: %s\r\n", content_type);
	sendstr(sockfd, buf);
}

int send_file(http_request *req, char *filename)
{
	char fullpath[4096];
	char *filepart;

	if (!filename || !*filename) {
		filename = "index.html";
	}

	if (GetFullPathNameA(filename, sizeof(fullpath) - 1, fullpath, &filepart) == 0||
	    filepart == NULL || /* directory */
	    _strnicmp(fullpath, webroot, strlen(webroot)))
	{
		return error404(req->sockfd);
	}

	HANDLE hFile = CreateFile(fullpath,              // file to open
	                          GENERIC_READ,          // open for reading
	                          FILE_SHARE_READ,       // share for reading
	                          NULL,                  // default security
	                          OPEN_EXISTING,         // existing file only
	                          FILE_ATTRIBUTE_NORMAL, // normal file
	                          NULL);                 // no attr. template


	if (hFile == INVALID_HANDLE_VALUE) {
		return error404(req->sockfd);
	}

	size_t filesize = GetFileSize(hFile, NULL);
	size_t buf_len = min(0x2000, filesize);

	char *buf = (char*)HeapAlloc(req->heap, 0, buf_len);
	if (!buf) {
		return error500(req->sockfd);
	}

	size_t remaining = filesize;
	char local_buf[50];

	send_response_headers(req->sockfd, "200 OK");
	content_type(req->sockfd, filename);
	sprintf_s(local_buf, sizeof(local_buf), "Content-Length: %zu\r\n\r\n", remaining);
	sendstr(req->sockfd, local_buf);

	while (remaining) {
		DWORD rc = 0;

		if (FALSE == ReadFile(hFile, buf, (DWORD)min(remaining, buf_len), &rc, NULL)) {
			break;
		}

		remaining -= rc;

		if (sendlen(req->sockfd, buf, rc) == SOCKET_ERROR) {
			break;
		}
	}

	CloseHandle(hFile);
	HeapFree(req->heap, 0, buf);

	return 200;
}

int connect_domain(char *domain, SOCKET *sockfd)
{
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL, *ptr = NULL, hints;
	int iResult;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(domain, "12345", &hints, &result);
	if (iResult != 0) {
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		// Create a SOCKET for connecting to server
		*sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (*sockfd == INVALID_SOCKET) {
			return 1;
		}

		// Connect to server.
		iResult = connect(*sockfd, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(*sockfd);
			*sockfd = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	return 0;
}

int page_login(http_request *req)
{
	char *username = dict_get(req->params, req->params_count, "username", 1);
	char *password = dict_get(req->params, req->params_count, "password", 1);
	char *domain = dict_get(req->params, req->params_count, "domain", 1);

	if (!username || !password || !domain) {
		return error403(req->sockfd);
	}

	int auth_success = 0;
	char buf[0x2000];
	ZeroMemory(buf, sizeof(buf));

	if (!*domain) { /* no domain */
		auth_success = !strcmp(username, "admin") && !strcmp(password, "admin");
	} else {
		SOCKET domain_sock = INVALID_SOCKET;

		if (strncmp(domain, "win.local", strlen("win.local")) ||
		    connect_domain(domain, &domain_sock) ||
		    domain_sock == INVALID_SOCKET) {
			return error500(req->sockfd);
		}

		setsock_timeout(domain_sock);
		sprintf_s(buf, sizeof(buf) - 1, "%s::%s\n", username, password);

		if (sendstr(domain_sock, buf) != SOCKET_ERROR) {
			ZeroMemory(buf, sizeof(buf));
			if (recvlen(domain_sock, buf, 3, NULL) != SOCKET_ERROR) {
				auth_success = strcmp(buf, "OK");
			}

			closesocket(domain_sock);
		} else {
			closesocket(domain_sock);
			return error500(req->sockfd);
		}
	}

	send_response_headers(req->sockfd, "200 OK");

	if (auth_success) {
		sprintf_s(buf, sizeof(buf) - 1, "Welcome back %s!", username);
	} else {
		sprintf_s(buf, sizeof(buf) - 1, "Authentication failure");
	}

	send_response_body(req->sockfd, buf);

	return 200;
}

void extract_params(http_request *req, char *start, char *end)
{
	char *ptr;
	char *params_cursor = start;
	char *key = NULL;
	char *value = NULL;
	size_t value_size = 0;

	for (ptr = params_cursor; ptr <= end; ptr++) {
		if (ptr == end || *ptr == '&') {
			*ptr = '\0';

			if (!key) { /* no value specified */
				if (*params_cursor) {
					key = params_cursor;
					value_size = 0;
				}
			} else {
				value = params_cursor;
				value_size = urldecode(value, value);
			}

			if (key) {
				dict_add(req, &req->params, &req->params_count, key, value, value_size);
			}

			key = NULL;
			value = NULL;
			params_cursor = ptr + 1;
		} else if (*ptr == '=') {
			*ptr = '\0';
			if (*params_cursor) {
				key = params_cursor;
			} else {
				key = NULL;
			}
			params_cursor = ptr + 1;
		}
	}
}

int parse_headers(http_request *req, char *start, char *end)
{
	char *cursor = start;
	char *line_end;
	char *ptr;

	/* Read the first line */
	for (line_end = cursor; (line_end + 1 < end) && !(line_end[0] == '\r' && line_end[1] == '\n'); line_end++);

	/* Extract Method */
	for (ptr = cursor; ptr < line_end && *ptr != ' '; ptr++);
	*ptr = '\0';
	strcpy_n(req->method, cursor, sizeof(req->method));

	if (strcmp(req->method, "GET") && strcmp(req->method, "POST")) {
		return error505(req->sockfd);
	}

	for (cursor = ptr + 1; cursor < line_end && *cursor == ' '; cursor++); // skip spaces

	/* Extract filename */

	for (ptr = cursor; ptr < line_end && *ptr != ' ' && *ptr != '?'; ptr++);
	char tmp = *ptr;
	*ptr = '\0';
	strcpy_n(req->filename, cursor, sizeof(req->filename));

	if (*req->filename != '/') {
		return error400(req->sockfd);
	}

	char *get_params = NULL;

	if (tmp == '?') {
		*ptr = '?';
		get_params = ptr + 1;
		for (; ptr < line_end && *ptr != ' '; ptr++);
		*ptr = 0;
	}

	req->query_string = (char*)HeapAlloc(req->heap, 0, ptr - cursor + 1);
	strcpy_n(req->query_string, cursor, ptr - cursor);

	/* Extract params from query string */

	char *key = NULL;
	char *value = NULL;
	cursor = ptr;

	if (get_params) {
		extract_params(req, get_params, cursor);
	}

	/* Extract protocol */

	for (cursor = cursor + 1; cursor < line_end && *cursor == ' '; cursor++); // skip spaces
	for (ptr = cursor; ptr < line_end && *ptr != '\r'; ptr++);
	*ptr = '\0';
	strcpy_n(req->protocol, cursor, sizeof(req->protocol));

	if (strcmp(req->protocol, "HTTP/1.0") && strcmp(req->protocol, "HTTP/1.1")) {
		return error505(req->sockfd);
	}

	/* Extract all headers */

	cursor = line_end + 2;

	while (cursor < end) {
		for (line_end = cursor; line_end + 1 < end && !(line_end[0] == '\r' && line_end[1] == '\n'); line_end++);

		for (ptr = cursor; ptr < line_end && *ptr != ':'; ptr++);
		*ptr = '\0';
		key = cursor;
		for (cursor = ptr + 1; cursor < line_end && *cursor == ' '; cursor++); // skip spaces
		value = cursor;
		*line_end = '\0';

		dict_add(req, &req->headers, &req->headers_count, key, value, strlen(value) + 1);
		if (!_stricmp(key, "Host") && !*req->hostname) {
			strcpy_n(req->hostname, value, sizeof(req->hostname));
		} else if (!_stricmp(key, "Content-Length")) {
			req->content_length = atoll(value);
		}
		cursor = line_end + 2;
	}

	return 0;
}

DWORD WINAPI handle_client(SOCKET sockfd)
{
	printf("Handling new client...\n");

	HANDLE hHeap = HeapCreate(0, 0, 0);
	char *req_head = (char*)HeapAlloc(hHeap, 0, MAX_HEADERS_LENGTH);
	ZeroMemory(req_head, MAX_HEADERS_LENGTH);

	http_request *req = (http_request*) HeapAlloc(hHeap, 0, sizeof(http_request));
	ZeroMemory(req, sizeof(http_request));
	req->heap = hHeap;
	req->sockfd = sockfd;

	int rc = recvlen(sockfd, req_head, MAX_HEADERS_LENGTH - 1, "\r\n\r\n");

	if (rc <= 0) {
		goto end;
	}

	char *req_head_end = strstr(req_head, "\r\n\r\n");
	if (!req_head_end) {
		if (rc == MAX_HEADERS_LENGTH - 1) {
			error413(sockfd);
		} else {
			error400(sockfd);
		}
		goto end;
	}

	if (parse_headers(req, req_head, req_head_end + 2)) {
		/* error already sent via parse_headers() */
		goto end;
	}

	/* Check if the file exists or if its a valid page */

	char *filename;
	for (filename = req->filename; *filename == '/'; filename++);
	if (!*filename) {
		filename = "index.html";
	}

	int(*callback)(http_request *) = NULL;

	for (int i = 0; i < _countof(endpoints); i++) {
		if (!strcmp(filename, endpoints[i].name)) {
			callback = endpoints[i].func;
			break;
		}
	}

	int res;

	if (!callback) {
		res = send_file(req, filename);
	} else {
		/* read POST content */

		if (!strcmp(req->method, "POST") && req->content_length > 0) {
			if (req->content_length > 0x10000) {
				error413(req->sockfd);
				goto end;
			}
			req->content = (char*)HeapAlloc(hHeap, 0, req->content_length + 1);
			req->content[req->content_length] = '\0';

			size_t already_read = rc - (req_head_end + 4 - req_head);

			if (already_read >= req->content_length) {
				memcpy(req->content, req_head_end + 4, req->content_length);
			} else {
				memcpy(req->content, req_head_end + 4, already_read);
				size_t remaining = req->content_length - already_read;

				if (recvlen(req->sockfd, req->content + already_read, (DWORD)remaining, NULL) != remaining) {
					error500(req->sockfd);
					goto end;
				}
			}

			extract_params(req, req->content, req->content + req->content_length);
		}

		res = callback(req);
	}

	if (res != SOCKET_ERROR) {
		rc = shutdown(sockfd, SD_SEND);
	}

end:
	HeapFree(hHeap, 0, req->query_string);
	for (int i = 0; i < req->headers_count; i++) {
		HeapFree(hHeap, 0, req->headers[i].key);
		HeapFree(hHeap, 0, req->headers[i].value);
	}
	HeapFree(hHeap, 0, req->headers);
	for (int i = 0; i < req->params_count; i++) {
		HeapFree(hHeap, 0, req->params[i].key);
		HeapFree(hHeap, 0, req->params[i].value);
	}
	HeapFree(hHeap, 0, req->params);
	HeapFree(hHeap, 0, req->content);
	HeapFree(hHeap, 0, req);
	HeapFree(hHeap, 0, req_head);
	HeapDestroy(hHeap);

	closesocket(sockfd);

	EnterCriticalSection(&CriticalSection);
	ThreadCount--;
	LeaveCriticalSection(&CriticalSection);
	WakeByAddressAll(&ThreadCount);
	return 0;
}

int __cdecl main(int argc, char **argv)
{
	WSADATA wsaData;
	int iResult;

	if (argc != 3) {
		printf("Usage: %s <ip:port> <webroot>\n", argv[0]);
		return 1;
	}

	char *filepart;
	if (GetFullPathNameA(argv[2], sizeof(webroot) - 1, webroot, &filepart) == 0 ||
	    filepart != NULL) {
		printf("Invalid root directory '%s'\n", argv[2]);
		return 1;
	}

	printf("[+] Using '%s' as the web root\n", webroot);
	if (!SetCurrentDirectory(webroot)) {
		printf("[-] SetCurrentDirectory failed\n");
		return 1;
	}

	SOCKET ListenSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (iResult != 0) {
		printf("[-] WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, argv[1], &hints, &result);

	if (iResult != 0) {
		printf("[-] getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if (ListenSocket == INVALID_SOCKET) {
		printf("[-] socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);

	if (iResult == SOCKET_ERROR) {
		printf("[-] bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, MAX_THREADS);

	if (iResult == SOCKET_ERROR) {
		printf("[-] listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	InitializeCriticalSection(&CriticalSection);

	while (1) {
		// Accept a client socket
		SOCKET ClientSocket = INVALID_SOCKET;
		ClientSocket = accept(ListenSocket, NULL, NULL);

		if (ClientSocket == INVALID_SOCKET) {
			printf("[-] accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		setsock_timeout(ClientSocket);
		DWORD ThreadId;

		EnterCriticalSection(&CriticalSection);
		ThreadCount++;
		int CapturedValue = ThreadCount;
		LeaveCriticalSection(&CriticalSection);

		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)handle_client, (LPVOID)ClientSocket, 0, &ThreadId);

		int UndesiredValue = MAX_THREADS;
		while (CapturedValue == UndesiredValue) {
			WaitOnAddress(&ThreadCount, &UndesiredValue, sizeof(int), INFINITE);
			EnterCriticalSection(&CriticalSection);
			CapturedValue = ThreadCount;
			LeaveCriticalSection(&CriticalSection);
		}
	}

	DeleteCriticalSection(&CriticalSection);
	WSACleanup();

	closesocket(ListenSocket);

	return 0;
}
