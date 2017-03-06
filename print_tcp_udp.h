
void print_tcp(struct tcphdr* tcp, char* verb){
	char* flag;
	switch(tcp->th_flags){
		case TH_FIN :
			flag = "FIN";
			break;
		case TH_SYN:
			flag = "SYN";
			break;
		case TH_RST :
			flag = "RST";
			break;
		case TH_PUSH :
			flag = "PUSH";
			break;
		case TH_ACK :
			flag = "ACK";
			break;	
		case 0x18 :
			flag = "PUSH_ACK";
			break;	
		case 0x12 :
			flag = "SYN_ACK";
			break;	
		default :
			flag = ".";
			break;
	}



	if(!strcmp(verb,"1")){
		printf("..Src port: %d->", ntohs(tcp->th_sport));
		printf("Dst port: %d\n", ntohs(tcp->th_dport));
	}
	if(!strcmp(verb,"2")){
		printf("		Src port: %d->", ntohs(tcp->th_sport));
		printf("Dst port: %d ... %s\n", ntohs(tcp->th_dport), flag);

	}



	if(!strcmp(verb,"3")){
		printf("\n		Src port: %d\n", ntohs(tcp->th_sport));
		printf("		Dst port: %d\n", ntohs(tcp->th_dport));
		printf("		   Flags: %s\n", flag);
		printf("		SeqNum: %x | AckNum : %x | Offset %x \n",ntohl(tcp->th_seq),ntohl(tcp->th_ack),ntohs(tcp->th_off));
		}

}

void print_udp(struct udphdr* udp, char* verb){
	if(!strcmp(verb,"1")){
		printf("Src port: %d->", ntohs(udp->uh_sport));
		printf("Dst port: %d\n", ntohs(udp->uh_dport));
	}
	if(!strcmp(verb,"2")){
		printf("		Src port: %d->", ntohs(udp->uh_sport));
		printf("Dst port: %d .\n", ntohs(udp->uh_dport));
	}	
	if(!strcmp(verb,"3")){
		printf("\n		Src port: %d\n", ntohs(udp->uh_sport));
		printf("		Dst port: %d\n", ntohs(udp->uh_dport));
		printf("		Udp lenght: %d\n", ntohs(udp->uh_ulen));
		printf("		Udp Chcksum: %d\n", ntohs(udp->uh_sum));

		
	}

}
