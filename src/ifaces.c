/***************************************************************************
 *            ifaces.c
 *
 *  Mon Jun 27 04:56:42 2005
 *  Copyright 2005-2015 Jaime Penalba Estebanez <jpenalbae@gmail.com>
 *  Copyright 2007-2008 Gustavo Chain
 *  Copyright 2021      bcoles <bcoles@gmail.com>
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include <arpa/inet.h>

#include "screen.h"
#include "ifaces.h"
#include "data_al.h"


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef __linux__
#include <net/if_arp.h>
#else
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#endif


#define ARP_REPLY "\x00\x02"
#define ARP_REQUEST "\x00\x01"

#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#endif




/* Shitty globals */
pcap_t *inject;
unsigned char smac[] = { 0xCA, 0xFE, 0xCA, 0xFE, 0xCA, 0xFE };
struct p_header *temp_header;


/* Start Sniffing on given iface */
void *start_sniffer(void *args)
{
   pcap_t *descr;
   struct bpf_program fp;	
   struct t_data *datos; 
   char *filter;

   datos = (struct t_data *)args;

   /* Open interface. Immediate mode avoids BPF buffering delays
    * (notably on macOS/BSD, where packets are otherwise held until
    * the buffer fills or the timeout expires). */
   descr = pcap_create(datos->interface, errbuf);
   if(descr == NULL) {
      printf("pcap_create(): %s\n", errbuf);
      sighandler(0); // QUIT
   }
   pcap_set_snaplen(descr, BUFSIZ);
   pcap_set_promisc(descr, 1);
   pcap_set_timeout(descr, PCAP_TOUT);
   pcap_set_immediate_mode(descr, 1);
   if (pcap_activate(descr) < 0) {
      printf("pcap_activate(): %s\n", pcap_geterr(descr));
      pcap_close(descr);
      sighandler(0); // QUIT
   }

   /* Set pcap filter */
   filter = (datos->pcap_filter == NULL) ? "arp" : datos->pcap_filter;
   if(pcap_compile(descr, &fp, filter, 0, 0) == -1) {
      printf("pcap_compile(): %s\n", pcap_geterr(descr));
      sighandler(0); // QUIT
   }
   pcap_setfilter(descr, &fp);

   /* Start loop for packet capture */
   pcap_loop(descr, -1, (pcap_handler)process_packet, NULL);

   return NULL;
}


/* Handle packets recived from pcap_loop */
void process_packet(u_char *args, struct pcap_pkthdr* pkthdr,
                    const u_char* packet)
{
   struct p_header *new_header;
   new_header = (struct p_header *) malloc (sizeof(struct p_header));

   /* Get packet ethernet header data and fill struct */
   memcpy(new_header->dmac, packet, 6);         /* dest mac    */
   memcpy(new_header->smac, packet + 6, 6);     /* src mac     */
   new_header->length = pkthdr->len;            /* Packet size */

   /* Discard packets with our mac as source */
   if (memcmp(new_header->smac, smac, 6) == 0)
   {
     free(new_header);
     return;
   }

   unsigned char type[2];
   memcpy(type, packet + 20, 2);

   struct data_registry *new_reg;
   new_reg = (struct data_registry *) malloc (sizeof(struct data_registry));
   new_reg->header = new_header;
   new_reg->tlength = new_header->length;
   process_arp_header(new_reg, packet);

   /* Check if its ARP request or reply, and add it to list */
   if (memcmp(type, ARP_REPLY, 2) == 0) {
     new_reg->type = 2;             /* Arp Type */
     pthread_mutex_lock(data_access);
     _data_reply.add_registry(new_reg);
     pthread_mutex_unlock(data_access);

   } else if (memcmp(type, ARP_REQUEST, 2) == 0) {
     new_reg->type = 1;             /* Arp Type */
     pthread_mutex_lock(data_access);
     _data_request.add_registry(new_reg);
     pthread_mutex_unlock(data_access);

   } else {
     free(new_header);
     free(new_reg->sip);
     free(new_reg->dip);
     free(new_reg);
   }
}

/* Handle arp packet header */
void process_arp_header(struct data_registry *new_reg, const u_char* packet)
{

    /* Populate basic common registry info */
    new_reg->count = 1;
    new_reg->next = NULL;

    /* Allocate memory for ip addrs */
    new_reg->sip = (char *) malloc (sizeof(char) * 16);
    new_reg->dip = (char *) malloc (sizeof(char) * 16);

    /* Source IP */
    sprintf(new_reg->sip, "%d.%d.%d.%d",
            packet[28], packet[29], packet[30], packet[31]);

    /* Destination IP */
    sprintf(new_reg->dip, "%d.%d.%d.%d",
            packet[38], packet[39], packet[40], packet[41]);
}

/* Get our mac address */
void get_mac(char *disp)
{

#ifdef __linux__
  struct ifreq ifr;
  size_t if_name_len = strlen(disp);

  if (if_name_len < sizeof(ifr.ifr_name)) {
    memcpy(ifr.ifr_name, disp, if_name_len);
    ifr.ifr_name[if_name_len] = 0;
  } else {
    printf("interface name is too long");
    exit(1);
  }

  int fd = socket(AF_UNIX,SOCK_DGRAM,0);
  if (fd == -1) {
    printf("%s", strerror(errno));
    exit(1);
  }

  if (ioctl(fd,SIOCGIFHWADDR,&ifr) == -1) {
    int temp_errno = errno;
    close(fd);
    printf("%s", strerror(temp_errno));
    exit(1);
  }
  close(fd);

  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    printf("not an Ethernet interface");
    exit(1);
  }

  //unsigned char* mac = (unsigned char*) ;
  memcpy(smac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
#else
  /* BSD / macOS: read the link-layer address with getifaddrs() */
  struct ifaddrs *ifap, *ifa;
  int found = 0;

  if (getifaddrs(&ifap) == -1) {
    printf("getifaddrs(): %s\n", strerror(errno));
    exit(1);
  }

  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK ||
        strcmp(ifa->ifa_name, disp) != 0)
      continue;

    struct sockaddr_dl *sdl = (struct sockaddr_dl *) ifa->ifa_addr;
    if (sdl->sdl_type != IFT_ETHER || sdl->sdl_alen != ETH_ALEN)
      continue;

    memcpy(smac, LLADDR(sdl), ETH_ALEN);
    found = 1;
    break;
  }
  freeifaddrs(ifap);

  if (!found) {
    printf("%s: not an Ethernet interface\n", disp);
    exit(1);
  }
#endif
}


/* Init device for libpcap and get mac addr */
void inject_init(char *disp)
{
   char loc_errbuf[PCAP_ERRBUF_SIZE];

   /* Open interface for injection */
   inject = pcap_open_live(disp, BUFSIZ, 1, PCAP_TOUT, loc_errbuf);
   if(inject == NULL) {
      printf("pcap_open_live(): %s\n", loc_errbuf);
      exit(1);
   }

   get_mac(disp);
}


/* Forge Arp Packet, using libpcap */
void forge_arp(char *source_ip, char *dest_ip, char *disp)
{
   in_addr_t sip, dip;

	char raw_arp[] =
		"\xff\xff\xff\xff\xff\xff" // mac destination
		"\x00\x00\x00\x00\x00\x00" // mac source
		"\x08\x06"                 // type
		"\x00\x01"                 // hw type
		"\x08\x00"                 // protocol type
		"\x06"                     // hw size
		"\x04"                     // protocol size
		"\x00\x01"                 // opcode
		"\x00\x00\x00\x00\x00\x00" // sender mac
		"\x00\x00\x00\x00"         // sender ip
		"\xff\xff\xff\xff\xff\xff" // target mac
		"\x00\x00\x00\x00";        // target ip

   /* get src & dst ip address */
   dip = inet_addr(dest_ip);
   sip = inet_addr(source_ip);
	
	memcpy(raw_arp + 28, (char*) &sip, IP_ALEN);
	memcpy(raw_arp + 38, (char*) &dip, IP_ALEN);

	/* set mac addr */
	memcpy(raw_arp + 6,  smac, ETH_ALEN);
	memcpy(raw_arp + 22, smac, ETH_ALEN);

	/* Inject the packet */
	pcap_sendpacket(inject, (unsigned char *)raw_arp, sizeof(raw_arp) - 1);

}


void inject_destroy()
{
	pcap_close(inject);
}
