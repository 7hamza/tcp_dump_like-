int magic_cookie_dhcp(u_int8_t* bp_vend){
	
		if(bp_vend[0]==99 && bp_vend[1]==130 && bp_vend[2]==83 && bp_vend[3]==99){
			return 0;
		}
	return 1;
}


void print_dhcp(struct bootp* bootp){


	if(magic_cookie_dhcp(bootp->bp_vend)==0){
		printf("		DHCP--->");
		if(bootp->bp_vend[4] == TAG_DHCP_MESSAGE){
			switch (bootp->bp_vend[6]){
				case DHCPDISCOVER :
					printf("DISCOVER\n");
					break;
				case DHCPOFFER :
					printf("OFFER\n");
					break;
				case DHCPDECLINE :
					printf("DECLINE\n");
					break;
				case DHCPACK :
					printf("ACK\n");
					break;
				case DHCPNAK :
					printf("NACK\n");
					break;
				case DHCPRELEASE :
					printf("RELEASE\n");
					break;
				case DHCPINFORM :
					printf("INFORM\n");
					break;
			}
		} 
	} 

}


void print_bootp(struct bootp* bootp, char* verb){
	char* opcode;
	
	switch(bootp->bp_op){
		case 2 :
			opcode ="REPLY(2)";
			break;
		case 1:
			opcode ="REQUEST(1)";
			break;
	}

	

	if(!strcmp(verb,"1")){
		printf("		opcode: %s\n", opcode);			
	}

	if(!strcmp(verb,"2")){
		printf("		BOOTP opcode: %s....", opcode);
		printf("Client IP : %s->",inet_ntoa(bootp->bp_ciaddr));
		printf("Server IP : %s\n",inet_ntoa(bootp->bp_siaddr));
		
		
	}


	if(!strcmp(verb,"3")){
		printf("		BOOTP opcode: %s\n", opcode);
		printf("		Client IP : %s\n",inet_ntoa(bootp->bp_ciaddr));
		printf("		Your IP : %s\n",inet_ntoa(bootp->bp_yiaddr));
		printf("		Server IP : %s\n",inet_ntoa(bootp->bp_siaddr));
		printf("		Gateway IP : %s\n",inet_ntoa(bootp->bp_ciaddr));

	}
	
}

