/*
 *	client.c
 *  Release $Name: MATRIXSSL-3-4-2-OPEN $
 *
 *	Simple MatrixSSL blocking client example
 */
/*
 *	Copyright (c) 2013 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software 
 *	into proprietary programs.  If you are unable to comply with the GPL, a 
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/eng/Company/Locations
 *	
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include <time.h>
#include "app.h"
#include "matrixssl/matrixsslApi.h"

#ifdef USE_CLIENT_SIDE_SSL

#ifdef WIN32
#pragma message("DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS.")
#else
#warning "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
#endif

/*
	If supporting client authentication, pick ONE identity to auto select a
	certificate	and private key that support desired algorithms.
*/
#define ID_RSA /* RSA Certificate and Key */

#define USE_HEADER_KEYS
#define ALLOW_ANON_CONNECTIONS	1

/*	If the algorithm type is supported, load a CA for it */
#ifdef USE_HEADER_KEYS
/* CAs */
#include "sampleCerts/RSA/ALL_RSA_CAS.h"

/* Identity Certs and Keys for use with Client Authentication */
#ifdef ID_RSA
#define EXAMPLE_RSA_KEYS
#include "sampleCerts/RSA/2048_RSA.h"
#include "sampleCerts/RSA/2048_RSA_KEY.h"
#endif


/* File-based keys */
#else
/* CAs */
static char rsaCAFile[] = "../sampleCerts/RSA/ALL_RSA_CAS.pem";

/* Identity Certs and Keys for use with Client Authentication */
#ifdef ID_RSA
#define EXAMPLE_RSA_KEYS
static char rsaCertFile[] = "../sampleCerts/RSA/2048_RSA.pem";
static char rsaPrivkeyFile[] = "../sampleCerts/RSA/2048_RSA_KEY.pem";
#endif


#endif /* USE_HEADER_KEYS */

#include "base64.c"
typedef unsigned long long ticks;
extern unsigned char* pms;
extern size_t pms_len;


/* #define REHANDSHAKE_TEST */

/********************************** Globals ***********************************/

static unsigned char g_httpRequestHdr[] = "GET / HTTP/1.0\r\n"
	"User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
	"Accept: */*\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

/********************************** Defines ***********************************/

// #define HTTPS_IP				(char *)"127.0.0.1"
char ip[256];
unsigned int port = 0;

/****************************** Local Functions *******************************/

static int32 httpWriteRequest(ssl_t *ssl);
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert);
static SOCKET socketConnect(char *ip, int32 port, int32 *err);
static void closeConn(ssl_t *ssl, SOCKET fd);

#ifdef USE_CRL
static int32 crlCb(psPool_t *pool, psX509Cert_t *CA, int append,
				char *url, uint32 urlLen);
#endif


/******************************************************************************/
/*
	Make a secure HTTP request to a defined IP and port
	Connection is made in blocking socket mode
	The connection is considered successful if the SSL/TLS session is
	negotiated successfully, a request is sent, and a HTTP response is received.
 */
static int32 httpsClientConnection(sslKeys_t *keys, sslSessionId_t *sid)
{
	int32			rc, transferred, len, complete;
	ssl_t			*ssl;
	unsigned char	*buf;
	httpConn_t		cp;
	SOCKET			fd;
	
        unsigned long long start = 0;
        unsigned long long end   = 0;
        unsigned long      minor = 0;
        unsigned long      mayor = 0;

	complete = 0;
	memset(&cp, 0x0, sizeof(httpConn_t));
	// fd = socketConnect(HTTPS_IP, HTTPS_PORT, &rc);
	fd = socketConnect(ip, port, &rc);
	if (fd == INVALID_SOCKET || rc != PS_SUCCESS) {
                printf("ERROR: connent to %s:%u failed\n", ip, port);
		_psTraceInt("Connect failed: %d.  Exiting\n", rc);
		return PS_PLATFORM_FAIL;
	}
	
	rc = matrixSslNewClientSession(&ssl, keys, sid, 0, certCb, NULL, NULL, 0);
	if (rc != MATRIXSSL_REQUEST_SEND) {
		_psTraceInt("New Client Session Failed: %d.  Exiting\n", rc);
		close(fd);
		return PS_ARG_FAIL;
	}
WRITE_MORE:
	while ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
		transferred = send(fd, buf, len, 0);

                // FIXME: Timestamp of the measurement start
                asm             volatile(
                                                         "cpuid \n"
                                                         "rdtsc"
                                         :               "=a"(minor),
                                                         "=d"(mayor)
                                         : "a" (0)
                                         : "%ebx", "%ecx"
                );
        
                start = ((((ticks) mayor) << 32) | ((ticks) minor));
                // Start timestamp now in "start"
        
                puts("$$$$$$$$$$$$$$ Were sending info");
		if (transferred <= 0) {
			goto L_CLOSE_ERR;
		} else {
			/* Indicate that we've written > 0 bytes of data */
			if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
				goto L_CLOSE_ERR;
			}
                        printf("$$$$$$$$$$$$$$ Got state: %d\n", rc);
			if (rc == MATRIXSSL_REQUEST_CLOSE) {
				closeConn(ssl, fd);
				return MATRIXSSL_SUCCESS;
			} 
			if (rc == MATRIXSSL_HANDSHAKE_COMPLETE) {
				/* If we sent the Finished SSL message, initiate the HTTP req */
				/* (This occurs on a resumption handshake) */
				if (httpWriteRequest(ssl) < 0) {
					goto L_CLOSE_ERR;
				}
				goto WRITE_MORE;
			}
			/* SSL_REQUEST_SEND is handled by loop logic */
		}
	}
READ_MORE:
	if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0) {
		goto L_CLOSE_ERR;
	}
	if ((transferred = recv(fd, buf, len, 0)) < 0) {
		goto L_CLOSE_ERR;
	}

                // FIXME: Timestamp of the measurement end
                asm             volatile(
                                                         "cpuid \n"
                                                         "rdtsc"
                                         :               "=a"(minor),
                                                         "=d"(mayor)
                                         : "a" (0)
                                         : "%ebx", "%ecx"
                );
        
                end = ((((ticks) mayor) << 32) | ((ticks) minor));
                // We got the data at the "end" timestamp
        

        printf("$$$$$$$$$$$$$$ We were receiving info after %llu ticks\n", end-start);
	/*	If EOF, remote socket closed. But we haven't received the HTTP response 
		so we consider it an error in the case of an HTTP client */
	if (transferred == 0) {
		goto L_CLOSE_ERR;
	}
	if ((rc = matrixSslReceivedData(ssl, (int32)transferred, &buf,
									(uint32*)&len)) < 0) {
		goto L_CLOSE_ERR;
	}
	
PROCESS_MORE:
	switch (rc) {
		case MATRIXSSL_HANDSHAKE_COMPLETE:
#ifdef REHANDSHAKE_TEST
/*
			Test rehandshake capabilities of server.  If a successful
			session resmption rehandshake occurs, this client will be last to
			send handshake data and MATRIXSSL_HANDSHAKE_COMPLETE will hit on
			the WRITE_MORE handler and httpWriteRequest will occur there.
			
			NOTE: If the server doesn't support session resumption it is
			possible to fall into an endless rehandshake loop
*/
			if (matrixSslEncodeRehandshake(ssl, NULL, NULL, 0, 0) < 0) {
				goto L_CLOSE_ERR;
			}
#else		
			/* We got the Finished SSL message, initiate the HTTP req */
			if (httpWriteRequest(ssl) < 0) {
				goto L_CLOSE_ERR;
			}
#endif
			goto WRITE_MORE;
		case MATRIXSSL_APP_DATA:
			if ((rc = httpBasicParse(&cp, buf, len)) < 0) {
				closeConn(ssl, fd);
				if (cp.parsebuf) free(cp.parsebuf); cp.parsebuf = NULL;
				cp.parsebuflen = 0;
				return MATRIXSSL_ERROR;
			}
			if (rc == HTTPS_COMPLETE) {
				rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len);
				closeConn(ssl, fd);
				if (cp.parsebuf) free(cp.parsebuf); cp.parsebuf = NULL;
				cp.parsebuflen = 0;
				if (rc < 0) {
					return MATRIXSSL_ERROR;
				} else {
					if (rc > 0) {
						_psTrace("HTTP data parsing not supported, ignoring.\n");
					}
					_psTrace("SUCCESS: Received HTTP Response\n");
					return MATRIXSSL_SUCCESS;
				}
			}
			/* We processed a partial HTTP message */
			if ((rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len)) == 0) {
				goto READ_MORE;
			}
			goto PROCESS_MORE;
		case MATRIXSSL_REQUEST_SEND:
			goto WRITE_MORE;
		case MATRIXSSL_REQUEST_RECV:
			goto READ_MORE;
		case MATRIXSSL_RECEIVED_ALERT:
			/* The first byte of the buffer is the level */
			/* The second byte is the description */
			if (*buf == SSL_ALERT_LEVEL_FATAL) {
				psTraceIntInfo("Fatal alert: %d, closing connection.\n", 
							*(buf + 1));
				goto L_CLOSE_ERR;
			}
			/* Closure alert is normal (and best) way to close */
			if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY) {
				closeConn(ssl, fd);
				if (cp.parsebuf) free(cp.parsebuf); cp.parsebuf = NULL;
				cp.parsebuflen = 0;
				return MATRIXSSL_SUCCESS;
			}
			psTraceIntInfo("Warning alert: %d\n", *(buf + 1));
			if ((rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len)) == 0) {
				/* No more data in buffer. Might as well read for more. */
				goto READ_MORE;
			}
			goto PROCESS_MORE;
		default:
			/* If rc <= 0 we fall here */
			goto L_CLOSE_ERR;
	}
	
L_CLOSE_ERR:
	_psTrace("FAIL: No HTTP Response\n");
	matrixSslDeleteSession(ssl);
	close(fd);
	if (cp.parsebuf) free(cp.parsebuf); cp.parsebuf = NULL;
	cp.parsebuflen = 0;
	return MATRIXSSL_ERROR;
}

/******************************************************************************/
/*
	Create an HTTP request and encode it to the SSL buffer
 */
static int32 httpWriteRequest(ssl_t *ssl)
{
	unsigned char   *buf;
	uint32          requested;
	int32			available;

	requested = strlen((char *)g_httpRequestHdr) + 1;
	if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0) {
		return PS_MEM_FAIL;
	}
	requested = min(requested, available);
	strncpy((char *)buf, (char *)g_httpRequestHdr, requested);
	_psTraceStr("SEND: [%s]\n", (char*)buf);
	if (matrixSslEncodeWritebuf(ssl, strlen((char *)buf)) < 0) {
		return PS_MEM_FAIL;
	}
	return MATRIXSSL_REQUEST_SEND;
}

/******************************************************************************/
/*
	Main routine. Initialize SSL keys and structures, and make two SSL 
	connections, the first with a blank session Id, and the second with
	a session ID populated during the first connection to do a much faster
	session resumption connection the second time.
 */
int32 main(int32 argc, char **argv)
{
	int32			rc, CAstreamLen, i;
	sslKeys_t		*keys;
	sslSessionId_t	*sid;
	char			*CAstream;
#ifdef USE_CRL
	int32			numLoaded;
#endif
#ifdef WIN32
	WSADATA			wsaData;
	WSAStartup(MAKEWORD(1, 1), &wsaData);
#endif


        if(argc != 4) {
                _psTrace("Usage: ./client IP PORT base64(pms)\n");
                return -1;
        }

        bzero(ip, sizeof(ip));
        strncpy(ip, argv[1], sizeof(ip)-1);

        port = atoi(argv[2]);
        if(port < 1 || port > 65535) {
                printf("Wrong port %u\n", (unsigned int) port);
                _psTrace("Wrong port\n");
                return -1;
        }

        pms = base64_decode(argv[3], strlen(argv[3]), &pms_len);

        if(pms == NULL || pms_len <= 0 || (pms_len % 128) != 0) {
                printf("Could not convert base64 encoded PMS with len %u\n", (unsigned int) pms_len);
                _psTrace("Could not convert base64 encoded PMS\n");
                return -1;
        }
        printf("PMS: ");
        for(i = 0; i < pms_len; i++) {
                printf("%c", pms[i]);
        }
        puts("");

	if ((rc = matrixSslOpen()) < 0) {
		_psTrace("MatrixSSL library init failure.  Exiting\n");
		return rc; 
	}
	if (matrixSslNewKeys(&keys) < 0) {
		_psTrace("MatrixSSL library key init failure.  Exiting\n");
		return -1;
	}

#ifdef USE_HEADER_KEYS
/*
	In-memory based keys
	Build the CA list first for potential client auth usage
*/
	CAstreamLen = 0;
	CAstreamLen += sizeof(RSACAS);
	if (CAstreamLen > 0) {
		CAstream = psMalloc(NULL, CAstreamLen);
	} else {
		CAstream = NULL;
	}
	
	CAstreamLen = 0;
	memcpy(CAstream, RSACAS, sizeof(RSACAS));
	CAstreamLen += sizeof(RSACAS);
		
#ifdef ID_RSA
	if ((rc = matrixSslLoadRsaKeysMem(keys, RSA2048, sizeof(RSA2048),
			RSA2048KEY, sizeof(RSA2048KEY), (unsigned char*)CAstream,
			CAstreamLen)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		if (CAstream) psFree(CAstream);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif
		

	if (CAstream) psFree(CAstream);

#else
/*
	File based keys
*/
	CAstreamLen = 0;
	CAstreamLen += (int32)strlen(rsaCAFile) + 1;
	if (CAstreamLen > 0) {
		CAstream = psMalloc(NULL, CAstreamLen);
		memset(CAstream, 0x0, CAstreamLen);
	} else {
		CAstream = NULL;
	}
	
	CAstreamLen = 0;
	memcpy(CAstream, rsaCAFile,	strlen(rsaCAFile));
	CAstreamLen += strlen(rsaCAFile);

/* Load Identiy */	
#ifdef EXAMPLE_RSA_KEYS	
	if ((rc = matrixSslLoadRsaKeys(keys, rsaCertFile, rsaPrivkeyFile, NULL,
			(char*)CAstream)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		if (CAstream) psFree(CAstream);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif	


	if (CAstream) psFree(CAstream);
#endif /* USE_HEADER_KEYS */


#ifdef USE_CRL
	if (matrixSslGetCRL(keys, crlCb, &numLoaded) < 0) {
		_psTrace("WARNING: A CRL failed to load\n");
	}
	_psTraceInt("CRLs loaded: %d\n", numLoaded);
#endif

	matrixSslNewSessionId(&sid);
	_psTrace("=== INITIAL CLIENT SESSION ===\n");
	httpsClientConnection(keys, sid);

	_psTrace("\n=== CLIENT SESSION WITH CACHED SESSION ID ===\n");
	httpsClientConnection(keys, sid);
	
	matrixSslDeleteSessionId(sid);
	matrixSslDeleteKeys(keys);
	matrixSslClose();

#ifdef WIN32
	_psTrace("Press any key to close");
	getchar();
#endif
	return 0;
}

/******************************************************************************/
/*
	Close a socket and free associated SSL context and buffers
	An attempt is made to send a closure alert
 */
static void closeConn(ssl_t *ssl, SOCKET fd)
{
	unsigned char	*buf;
	int32			len;
	
	/* Set the socket to non-blocking to flush remaining data */
#ifdef POSIX
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#elif WIN32
	len = 1;		/* 1 for non-block, 0 for block */
    ioctlsocket(fd, FIONBIO, &len);
#endif
	/* Quick attempt to send a closure alert, don't worry about failure */
	if (matrixSslEncodeClosureAlert(ssl) >= 0) {
		if ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
			if ((len = send(fd, buf, len, MSG_DONTWAIT)) > 0) {
				matrixSslSentData(ssl, len);
			}
		}
	}
	matrixSslDeleteSession(ssl);
	if (fd != INVALID_SOCKET) close(fd);
}

/******************************************************************************/
/*
	Example callback to do additional certificate validation.
	If this callback is not registered in matrixSslNewService,
	the connection will be accepted or closed based on the status flag.
 */
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
#ifdef POSIX
	struct tm	t;
	time_t		rawtime;
	char		*c;
	int			y, m, d;
#endif
	
	/* Example to allow anonymous connections based on a define */
	if (alert > 0) {
		if (ALLOW_ANON_CONNECTIONS) {
			_psTraceStr("Allowing anonymous connection for: %s.\n", 
						cert->subject.commonName);
			return SSL_ALLOW_ANON_CONNECTION;
		}
		_psTrace("Certificate callback returning fatal alert\n");
		return alert;
	}
	
#ifdef POSIX
	/* Validate the dates in the cert */
	time(&rawtime);
	localtime_r(&rawtime, &t);
	/* Localtime does months from 0-11 and (year-1900)! Normalize it. */
	t.tm_mon++;
	t.tm_year += 1900;
	
	/* Validate the 'not before' date */
	if ((c = cert->notBefore) != NULL) {
		if (strlen(c) < 8) {
			return PS_FAILURE;
		}
		/* UTCTIME, defined in 1982, has just a 2 digit year */
		if (cert->notBeforeTimeType == ASN_UTCTIME) {
			y =  2000 + 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		} else {
			y = 1000 * (c[0] - '0') + 100 * (c[1] - '0') + 
			10 * (c[2] - '0') + (c[3] - '0'); c += 4;
		}
		m = 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		d = 10 * (c[0] - '0') + (c[1] - '0'); 
		if (t.tm_year < y) return PS_FAILURE; 
		if (t.tm_year == y) {
			if (t.tm_mon < m) return PS_FAILURE;
			if (t.tm_mon == m && t.tm_mday < d) return PS_FAILURE;
		}
/*		_psTraceStr("Validated notBefore: %s\n", cert->notBefore); */
	}
	
	/* Validate the 'not after' date */
	if ((c = cert->notAfter) != NULL) {
		if (strlen(c) < 8) {
			return PS_FAILURE;
		}
		/* UTCTIME, defined in 1982 has just a 2 digit year */
		if (cert->notAfterTimeType == ASN_UTCTIME) {
			y =  2000 + 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		} else {
			y = 1000 * (c[0] - '0') + 100 * (c[1] - '0') + 
			10 * (c[2] - '0') + (c[3] - '0'); c += 4;
		}
		m = 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		d = 10 * (c[0] - '0') + (c[1] - '0'); 
		if (t.tm_year > y) return PS_FAILURE; 
		if (t.tm_year == y) {
			if (t.tm_mon > m) return PS_FAILURE;
			if (t.tm_mon == m && t.tm_mday > d) return PS_FAILURE;
		}
/*		_psTraceStr("Validated notAfter: %s\n", cert->notAfter); */
	}
#endif /* POSIX */
	_psTraceStr("Validated cert for: %s.\n", cert->subject.commonName);
	
	return PS_SUCCESS;
}

#ifdef USE_CRL
/* Basic example of matrixSslGetCRL callback for downloading a CRL from a given
	URL	and	passing	the CRL contents to matrixSslLoadCRL 
	
	< 0 - Error loading CRL
	> 0 - Success
*/ 
static unsigned char crl_getHdr[] = "GET ";
#define GET_OH_LEN		4
static unsigned char crl_httpHdr[] = " HTTP/1.0\r\n";
#define HTTP_OH_LEN		11
static unsigned char crl_hostHdr[] = "Host: ";
#define HOST_OH_LEN		6
static unsigned char crl_acceptHdr[] = "\r\nAccept: */*\r\n\r\n";
#define ACCEPT_OH_LEN	17

#define HOST_ADDR_LEN	64	/* max to hold 'www.something.com' */
#define GET_REQ_LEN		128	/* max to hold http GET request */
#define CRL_BUF_SIZE	4096	/* max size of incoming CRL */

int32 crlCb(psPool_t *pool, psX509Cert_t *CA, int append, char *url,
				uint32 urlLen)
{
	SOCKET			fd;
	struct hostent	*ip;
	struct in_addr	intaddr;
	char			*pageStart, *replyPtr, *ipAddr;
	char			hostAddr[HOST_ADDR_LEN], getReq[GET_REQ_LEN];
	char			crlBuf[CRL_BUF_SIZE];
	int				hostAddrLen, getReqLen, pageLen;
	int32			transferred;
	int32			err, httpUriLen, port, offset;
	uint32			crlBinLen;
	
	/* Is URI in expected URL form? */
	if (strstr(url, "http://") == NULL) {
		if (strstr(url, "https://") == NULL) {
			_psTraceStr("crlCb: Unsupported CRL URI: %s\n", url);
			return -1;
		}
		httpUriLen = 8;
		port = 80; /* No example yet of using SSL to fetch CRL */
	} else {
		httpUriLen = 7;
		port = 80;
	}
	
	/* Parsing host and page and setting up IP address and GET request */
	if ((pageStart = strchr(url + httpUriLen, '/')) == NULL) {
		_psTrace("crlCb: No host/page divider found\n");
		return -1;
	}
	if ((hostAddrLen = (int)(pageStart - url) - httpUriLen) > HOST_ADDR_LEN) {
		_psTrace("crlCb: HOST_ADDR_LEN needs to be increased\n");
		return -1; /* ipAddr too small to hold */
	}
	
	memset(hostAddr, 0, HOST_ADDR_LEN);
	memcpy(hostAddr, url + httpUriLen, hostAddrLen);
	if ((ip = gethostbyname(hostAddr)) == NULL) {
		_psTrace("crlCb: gethostbyname failed\n");
		return -1;
	}
	
	memcpy((char *) &intaddr, (char *) ip->h_addr_list[0],
        (size_t) ip->h_length);
	if ((ipAddr = inet_ntoa(intaddr)) == NULL) {
		_psTrace("crlCb: inet_ntoa failed\n");
		return -1;
	}
	
	pageLen = (urlLen - hostAddrLen - httpUriLen);
	getReqLen = pageLen + hostAddrLen + GET_OH_LEN + HTTP_OH_LEN +
		HOST_OH_LEN + ACCEPT_OH_LEN;
	if (getReqLen > GET_REQ_LEN) {
		_psTrace("crlCb: GET_REQ_LEN needs to be increased\n");
		return -1;
	}
	
	// Build the request:
	//
	//	GET /page.crl HTTP/1.0
	//	Host: www.host.com
	//	Accept: */*
	//	
	memset(getReq, 0, GET_REQ_LEN);
	memcpy(getReq, crl_getHdr, GET_OH_LEN);
	offset = GET_OH_LEN;
	memcpy(getReq + offset, pageStart, pageLen);
	offset += pageLen;
	memcpy(getReq + offset, crl_httpHdr, HTTP_OH_LEN);
	offset += HTTP_OH_LEN;
	memcpy(getReq + offset, crl_hostHdr, HOST_OH_LEN);
	offset += HOST_OH_LEN;
	memcpy(getReq + offset, hostAddr, hostAddrLen);
	offset += hostAddrLen;
	memcpy(getReq + offset, crl_acceptHdr, ACCEPT_OH_LEN);
	
	/* Connect and send */
	fd = socketConnect(ipAddr, port, &err);
	if (fd == INVALID_SOCKET || err != PS_SUCCESS) {
		_psTraceInt("crlCb: socketConnect failed: %d\n", err);
		return PS_PLATFORM_FAIL;
	}

	/* Send request and receive response */
	offset = 0;
	while (getReqLen) {
		if ((transferred = send(fd, getReq + offset, getReqLen, 0)) < 0) {
			_psTraceInt("crlCb: socket send failed: %d\n", errno);
			close(fd);
			return PS_PLATFORM_FAIL;
		}
		getReqLen -= transferred;
		offset += transferred;
	}
	
	/* Not a good full recv */
	if ((transferred = recv(fd, crlBuf, CRL_BUF_SIZE, 0)) <= 0) {
		_psTrace("crlCb: socket recv closed or failed\n");
		close(fd);
		return PS_PLATFORM_FAIL;
	} 
	if (transferred == CRL_BUF_SIZE) {
		/* CRL larger than max */
		_psTrace("crlCb: CRL_BUF_SIZE needs to be increased\n");
		close(fd);
		return -1;
	}
	close(fd);
	
	/* Did we get an OK response? */
	if (strstr(crlBuf, "200 OK") == NULL) {
		_psTrace("crlCb: server reply was not '200 OK'\n");
		return -1;
	}
	/* Length parse */
	if ((replyPtr = strstr(crlBuf, "Content-Length: ")) == NULL) {
		return -1;
	}
	crlBinLen = (int)atoi(replyPtr + 16);
	
	/* Data begins after CRLF CRLF */
	if ((replyPtr = strstr(crlBuf, "\r\n\r\n")) == NULL) {
		return -1;
	}
	/* A sanity test that the length matches the remainder */
	if ((transferred - (replyPtr - crlBuf) - 4) != crlBinLen) {
		return -1;
	}
	
	/* Lastly, pass the CRL to matrixSslLoadCRL to parse, perform signature
		validation, and cache the revoked certificates for this CA */
	return matrixSslLoadCRL(pool, CA, append, replyPtr + 4, crlBinLen);
}
#endif

/******************************************************************************/
/*
	Open an outgoing blocking socket connection to a remote ip and port.
	Caller should always check *err value, even if a valid socket is returned
 */
static SOCKET socketConnect(char *ip, int32 port, int32 *err)
{
	struct sockaddr_in	addr;
	SOCKET				fd;
	int32				rc;
	
	/* By default, this will produce a blocking socket */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		_psTrace("Error creating socket\n");
		*err = SOCKET_ERRNO;
		return INVALID_SOCKET;
	}
	
	memset((char *) &addr, 0x0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((short)port);
	addr.sin_addr.s_addr = inet_addr(ip);
	rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		*err = SOCKET_ERRNO;
	} else {
		*err = 0;
	}
	return fd;
}

#else

/******************************************************************************/
/* 
    Stub main for compiling without client enabled
*/
int32 main(int32 argc, char **argv)
{
    printf("USE_CLIENT_SIDE_SSL must be enabled in matrixsslConfig.h at build" \
            " time to run this application\n");
    return -1;
}
#endif /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/

