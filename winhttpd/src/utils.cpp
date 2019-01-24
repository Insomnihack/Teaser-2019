#include "stdafx.h"
#include "winhttpd.h"

void setsock_timeout(SOCKET sockfd)
{
	DWORD timeout = SOCKET_TIMEOUT;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
}

char *strcpy_n(char *dest, char *src, size_t n)
{
	char *res = dest;

	for (; *src && n; n--) {
		*dest++ = *src++;
	}
	*dest = '\0';

	return res;
}

int sendlen(SOCKET sockfd, const char *buf, size_t n)
{
	int rc;
	int nsent = 0;

	while (nsent < n)
	{
		rc = send(sockfd, buf + nsent, n - nsent, 0);

		if (rc == -1) {
			int error = WSAGetLastError();
			if (errno == WSAEWOULDBLOCK || error == WSAEINTR) {
				continue;
			}
			return SOCKET_ERROR;
		}

		nsent += rc;
	}
	return nsent;
}

int sendstr(SOCKET sockfd, const char *str)
{
	return sendlen(sockfd, str, strlen(str));
}

int recvlen(SOCKET sockfd, char *buf, int n, char *stop)
{
	int rc;
	int nread = 0;

	while (nread < n)
	{
		rc = recv(sockfd, buf + nread, n - nread, 0);

		if (rc == SOCKET_ERROR) {
			int error = WSAGetLastError();
			if (errno == WSAEWOULDBLOCK || error == WSAEINTR) {
				continue;
			}
			return SOCKET_ERROR;
		}

		if (rc == 0) {
			break;
		}

		nread += rc;

		if (stop && strstr(buf, stop)) {
			break;
		}
	}
	return nread;
}

size_t urldecode(char *dst, const char *src)
{
	char a;
	char b;
	char *orig = dst;

	while (*src)
	{
		if ((*src == '%' && src[1] && src[2]) &&
		    ((a = src[1]) && (b = src[2])) &&
		    (isxdigit(a) && isxdigit(b))) {

			if (a >= 'a') {
				a = a - 'a' + 10;
			} else if (a >= 'A') {
				a = a - 'A' + 10;
			} else {
				a -= '0';
			}

			if (b >= 'a') {
				b = b - 'a' + 10;
			} else if (b >= 'A') {
				b = b - 'A' + 10;
			} else {
				b -= '0';
			}

			*dst++ = a << 4 | b;
			src += 3;
		}
		else if (*src == '+') {
			*dst++ = ' ';
			src++;
		}
		else {
			*dst++ = *src++;
		}
	}

	*dst++ = 0;

	return dst - orig;
}

char *dict_get(dictionary dict, size_t dict_size, const char *key, int case_sensitive)
{
	for (size_t i = 0; i < dict_size; i++) {
		if (case_sensitive) {
			if (!strcmp(key, dict[i].key)) {
				return dict[i].value;
			}
		} else {
			if (!_stricmp(key, dict[i].key)) {
				return dict[i].value;
			}
		}
	}

	return NULL;
}

void dict_add(http_request *req, dictionary *dict, size_t *counter,
              char *key, char *value, size_t value_size)
{
	int i;
	char *k = NULL, *v = NULL;
	int key_position = -1;

	for (i = 0; i < *counter; i++) {
		if (!strcmp((*dict)[i].key, key)) {
			k = (*dict)[i].key;
			v = (*dict)[i].value;
			key_position = i;
			break;
		}
	}

	if (!k) {
		size_t len = strlen(key);
		k = (char*)HeapAlloc(req->heap, 0, len + 1);
		strcpy_n(k, key, len);
	}

	if (!v) {
		v = (char*)HeapAlloc(req->heap, 0, value_size);
	} else if (strlen(v) + 1 < value_size) {
		v = (char*)HeapReAlloc(req->heap, 0, v, value_size);
	}

	if (value) {
		memcpy(v, value, value_size); /* unintended uninit var when value_size == 0, oops :p */
	}
	//v[value_size] = '\0';

	if (key_position != -1) {
		(*dict)[key_position].value = v;
	} else {
		(*counter)++;

		if (!*dict) {
			*dict = (dictionary)HeapAlloc(req->heap, 0, *counter * sizeof(dictionary_entry));
		}
		else {
			*dict = (dictionary)HeapReAlloc(req->heap, 0, *dict, *counter * sizeof(dictionary_entry));
		}

		(*dict)[*counter - 1].key = k;
		(*dict)[*counter - 1].value = v;
	}
}
