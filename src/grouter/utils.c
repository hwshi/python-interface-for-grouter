/*
 * utils.c (some utilities for processing IP functions)
 * AUTHOR: Muthucumaru Maheswaran
 * VERSION: Beta
 */

#include "grouter.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <slack/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * determine whether the given IP address is in the network given the
 * netmask
 * RETURNS 0 if IP address is in the given network, -1 otherwise.
 */
int compareIPUsingMask(uchar *ip_addr, uchar *network, uchar *netmask)
{
	int ip, mask, net_addr, net;
        
	COPY_IP((char*)&ip, ip_addr);
        COPY_IP((char*)&mask, netmask);
        COPY_IP((char*)&net, network);
        
        net_addr = htonl(ip) & htonl(mask);
        
        return net_addr ^ htonl(net);
}


char *IP2Dot(char *buf, uchar ip_addr[])
{
    struct in_addr ip;
    
    COPY_IP(&ip, ip_addr);
	 ip.s_addr = htonl(ip.s_addr);
    strcpy(buf, inet_ntoa(ip));
    
    return buf;
}



int Dot2IP(char *buf, uchar ip_addr[])
{
    in_addr_t ip;
    
    ip = ntohl(inet_addr(buf)); 
    COPY_IP(ip_addr, &ip);
    
    return EXIT_SUCCESS;
}


// This is unaltered by the endianess. We treat the MAC as a string.
int Colon2MAC(char *buf, uchar mac_addr[])
{
        unsigned int imac_addr[6];
        int i;

        sscanf(buf, "%x:%x:%x:%x:%x:%x", &(imac_addr[0]), &(imac_addr[1]), &(imac_addr[2]),
	       &(imac_addr[3]), &(imac_addr[4]), &(imac_addr[5]));

        for (i=0; i < 6; i++) mac_addr[i] = imac_addr[i];
        return EXIT_SUCCESS;
}



char *MAC2Colon(char *buf, uchar mac_addr[])
{

	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);
	return buf;
}

char *MAC2String(char *buf, uchar mac_addr[])
{
    sprintf(buf, "%02x%02x%02x%02x%02x%02x", mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);
    return buf;
}

int gAtoi(char *str)
{
	int val = 0;
	int indx = 1, i;

	for (i = strlen(str); i >= 0; i--)
	{
		if ((str[i] <= '9') && (str[i] >= '0'))
		{
			val += indx * (str[i] - '0');
			indx *= 10;
		}
	}
	return val;
}





unsigned char *gHtonl(unsigned char tbuf[], unsigned char val[])
{
	long inpara, outpara;

	memcpy(&inpara, val, 4);
	outpara = htonl(inpara);
	memcpy(tbuf, &outpara, 4);

	return tbuf;
}


unsigned char *gNtohl(unsigned char tbuf[], unsigned char val[])
{
	long inpara, outpara;

	memcpy(&inpara, val, 4);
	outpara = ntohl(inpara);
	memcpy(tbuf, &outpara, 4);

	return tbuf;
}


/*
 * Redefine signal handlers
 */
void redefineSignalHandler(int sigid, void (*my_func)(int signum))
{
	struct sigaction handler, old_handler;

	handler.sa_handler = my_func;
	sigemptyset(&handler.sa_mask);
	handler.sa_flags = 0;

	sigaction(sigid, NULL, &old_handler);
	if (old_handler.sa_handler != SIG_IGN)
		sigaction(sigid, &handler, NULL);
	else
		verbose(1, "[redefineSignalHandler]:: signal %d is already ignored.. redefinition ignored ", sigid);

}



/*
 * compute the checksum of a buffer, by adding 2-byte words
 * and returning their one's complement
 */
ushort checksum(uchar *buf, int iwords)
{
	unsigned long cksum = 0;
	int i;

	for(i = 0; i < iwords; i++)
	{
		cksum += buf[0] << 8;
		cksum += buf[1];
		buf += 2;
	}

	// add in all carries
	while (cksum >> 16)
		cksum = (cksum & 0xFFFF) + (cksum >> 16);

	verbose(2, "[checksum]:: computed %x ..", ~cksum);

	return (unsigned short) (~cksum);
}

double subTimeVal(struct timeval *v2, struct timeval *v1)
{
	double val2, val1;

	val2 = v2->tv_sec * 1000.0 + v2->tv_usec/1000.0;
	val1 = v1->tv_sec * 1000.0 + v1->tv_usec/1000.0;

	return (val2 - val1);
}


void printTimeVal(struct timeval *v)
{
	printf("Time val = %d sec, %d usec \n", (int)v->tv_sec, (int)v->tv_usec);
}





