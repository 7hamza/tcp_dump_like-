void print_ip(struct ip *ip, u_char* verb){

	if(!strcmp(verb,"1")){
		printf("%s>%s", inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));
	}

	if(!strcmp(verb,"2")){
		printf("		From: %s->", inet_ntoa(ip->ip_src));
		printf("To: %s\n", inet_ntoa(ip->ip_dst));
	}
	if(!strcmp(verb,"3")){
		printf("\n		Version %d | IHL %d \n", ip->ip_v, ip->ip_hl);
		printf("		From: %s\n", inet_ntoa(ip->ip_src));
		printf("		  To: %s\n", inet_ntoa(ip->ip_dst));
		printf("		  Total lenght: %d\n", ntohs(ip->ip_len));


	}
}



void print_arp(struct arphdr* arp, u_char* verb){
	char* opcode;
	switch (ntohs(arp->ar_op)){
		case 1 :
			opcode = "REQUEST(1)";
			break;
		case 2 :
			opcode = "REPLY(2)";
			break;
		case 3 :
			opcode = "RREQUEST(3)";
			break;
		case 4 :
			opcode = "RREPLY(4)";
			break;
		case 8 :
			opcode = "InREQUEST(08)";
			break;
		case 9 :
			opcode = "InREPLY(09)";
			break;
		case 10 :
			opcode = "NAK(10)";
			break;
		

	}

	if(!strcmp(verb,"2") || !strcmp(verb,"1")){
		printf("	opcode 			  : %s\n", opcode);
	}

	if(!strcmp(verb,"3")){
		printf("	Format Adress hardware: %2d\n", ntohs(arp->ar_hrd));
		printf("	Format Adress protocol: %2d\n", ntohs(arp->ar_pro));
		printf("	ARP opcode 			  : %s\n", opcode);
		//printf(" 	Sender hardware adress: %c\n", _ntoa(arp->__ar_sha[6]));
	}		
}
