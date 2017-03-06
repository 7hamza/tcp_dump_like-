
// print ligne ::   offset		hexa 	ascii

void print_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hexa */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		
	}
	/* ligne < 8bits*/
	if (len < 8)
		printf(" ");
	
	/* remplire d'espace si ligne < 16 bits*/
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	//ascii
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}


// print trame ::   offset		hexa 	ascii	

void print_trame(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			
	int line_len;
	int offset = 0;					
	const u_char *ch = payload;

	if (len <= 0)
		return;

	if (len <= line_width) {
		print_line(ch, len, offset);
		return;
	}

	while(1) {
		line_len = line_width % len_rem;
		print_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			print_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
