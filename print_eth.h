void print_ethernet(struct ether_header *ethernet, u_char* verb){

	if(!strcmp(verb,"1"))
		printf("	Ethernet %s>%s",ether_ntoa((struct ether_addr *) &ethernet->ether_shost),ether_ntoa((struct ether_addr *) &ethernet->ether_dhost));
		
	if(!strcmp(verb,"2")){

		printf("	Ethernet....");	
		printf("		From: %s->", ether_ntoa((struct ether_addr *) &ethernet->ether_shost));
		printf(" To: %s\n", ether_ntoa((struct ether_addr *) &ethernet->ether_dhost));
	}

	if(!strcmp(verb,"3")){
		printf("	Ethernet....\n");
		printf("		From: %s\n", ether_ntoa((struct ether_addr *) &ethernet->ether_shost));
		printf("		  To: %s\n", ether_ntoa((struct ether_addr *) &ethernet->ether_dhost));
	
		
	}

}
