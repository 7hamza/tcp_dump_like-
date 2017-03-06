#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "bootp.h"

#include <string.h>
#include <unistd.h>

#include "print_trame.h"
#include "print_eth.h"
#include "print_ip_arp.h"
#include "print_tcp_udp.h"
#include "print_bootp.h"


#define MTU 1518 

#define SIZE_ETHERNET 14 


//Fonction callback +verbosite en args
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	



	static int count = 1;
	int size_ip; //taille entete ip
	int size_tcp; //taille tcp
	 
	
	printf("\nPacket Num %d:\n", count);
	count++;

	struct ether_header *ethernet;

	ethernet = (struct ether_header*)(packet);

	print_ethernet(ethernet,args);


	//IP ou ARP
	if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
        printf("	IP..........");
		struct ip *ip;
		
		ip = (struct ip*)(packet + SIZE_ETHERNET); 
		print_ip(ip,args);
		
		
		size_ip =  ip->ip_hl*4; 

		//TCP UDP ICMP IP 
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				printf("	Protocol: TCP");
				struct tcphdr* tcp;
				tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = tcp->th_off*4;
				print_tcp(tcp,args);

				//Pointer sur la data du packet
				const u_char * p = (const u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp ) ;

				if (ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) ==80 ){
					
					printf("	Protocol: HTTP\n");
					if(!strcmp(args,"3"))
						printf("%s\n", p );
					
				}

				if(ntohs(tcp->th_sport) == 25 || ntohs(tcp->th_dport) ==25 ){
					printf("	Protocol: SMTP\n");
					if(!strcmp(args,"3"))
						printf("%s\n", p );

				}
				if(ntohs(tcp->th_sport) == 21 || ntohs(tcp->th_dport) ==21 || ntohs(tcp->th_sport) == 20 || ntohs(tcp->th_dport) ==20 ){
					printf("	Protocol: FTP\n");
					if(!strcmp(args,"3"))
						printf("%s\n", p );

				}
				if(ntohs(tcp->th_sport) == 53 || ntohs(tcp->th_dport) ==53 ){
					const u_char * p_udp = (const u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp ) ;
					printf("	Protocol: DNS\n");		
				}
			   
			   
				break;
			case IPPROTO_UDP:
				printf("	Protocol: UDP");
				struct udphdr* udp;
				int size_udp;
				udp = (struct udphdr*)((packet + SIZE_ETHERNET + size_ip));
				print_udp(udp,args);
				// Cas des port pour couche applicative 
				if ((ntohs(udp->uh_sport) == 67) || (ntohs(udp->uh_dport) == 68)){ //check si bootp
					
					printf("	Protocol: BOOTP\n");
					
					struct bootp* bootp;
					
					bootp = (struct bootp*)(packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr) );
					
					print_bootp(bootp,args);

					print_dhcp(bootp);
				}
				//pointer sur la data si HTTP, SMTP sur UDP
				
				if (ntohs(udp->uh_sport) == 80 || ntohs(udp->uh_dport) ==80 ){
					const u_char * p_udp = (const u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr) ) ;
	
					printf("	Protocol: HTTP\n");
					if(!strcmp(args,"3"))
						printf("%s\n", p_udp );

					
				}

				if(ntohs(udp->uh_sport) == 25 || ntohs(udp->uh_dport) ==25 ){
					const u_char * p_udp = (const u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr) ) ;
					printf("	Protocol: SMTP\n");
					if(!strcmp(args,"3"))
						printf("%s\n", p_udp );

				}
				if(ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) ==53 ){
					const u_char * p_udp = (const u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr) ) ;
					printf("	Protocol: DNS\n");
					
				}
			   

				break;
			case IPPROTO_ICMP:
				printf("	Protocol: ICMP\n");
				break;
			case IPPROTO_IP:
				printf("	Protocol: IP\n");
				break;
			default:
				printf("	Protocol: unknown\n");
				break;
		}


	if(!strcmp(args,"3")){
		print_trame(packet, header->len);
	}
	//Vider la trame 
	memset((void *)packet, 0, header->len);


 } else  if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
        printf("	ARP.........\n");
        struct arphdr* arp;
        arp = (struct arphdr*)(packet +  SIZE_ETHERNET) ;
        print_arp(arp,args);
        if(!strcmp(args,"3")){
			print_trame(packet, header->len);
		}
  
    }


 	printf("\n###########################################################################");
	return;




}