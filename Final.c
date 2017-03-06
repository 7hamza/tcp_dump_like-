#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>

#include "callback.h"







void usage();

void usage(){
	printf("\nUsage 		  :sudo ./noob_pcap -i <interface>  -v <1..3> -f <filtre>\n");
	printf("Usage offline :sudo ./noob_pcap -o <fichier>   -v <1..3> -f <filtre> \n\n");
}



int main(int argc, char *argv[])
{
	int c;
	extern char *optarg;
	extern int optind, optopt;
	int err=0;
	int o=0,i=0,f=0;

	char *interface;
	char *filename;
	char* filter;
	u_char* verb;




	while((c=getopt(argc,argv,"i:o:f:v:"))!=-1){

		switch(c) {
			case 'i' :
				interface = optarg;
				i++;
				printf("interface choisi : %s\n", interface);
				break;

			case 'o' :
				filename = optarg;
				o++;
				printf("File choisi : %s\n", filename);
				break;	

			case 'f' :
				filter = optarg;
				f++;
				printf("Filter choisi  : %s\n", filter);
				break;	

			case 'v' :
				verb = optarg;
				printf("Verbosité choisie %s\n", verb);
				if(strcmp(verb,"1") && strcmp(verb,"2") && strcmp(verb,"3")){
					printf("Vrbosite invalide\n");
					usage();
					exit(1);
				}
					
				 break;	

			case ':' :	
				printf("Pas d'options choisies pour -%c\n", optopt);
				break;

			case '?' :
				printf("Erreur -%c\n", optopt);
				if(optopt=='v'){
					usage();
					exit(1);
				}
				break;

			
		}

	}


	//gestion d'err ligne de commande
	if(err || (o && i)){
		usage();
		exit(1);

	 }

	 if(o==0 && i == 0){
	 	printf("\n\nAucun fichier ou interface choisis\n");
	 	usage();
		exit(1);

	 }
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	pcap_t *handle;				/* packet capture handle */

	bpf_u_int32 mask;			/* mask */
	bpf_u_int32 net;			/* ip addr */

		
	


	

	//capture sur l'interface
	if(i){
		printf("Device: %s\n", interface);

		/* ip address et netmask de l'interface de capture */
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Erreur lecture netmask de l'interface %s: %s\n",interface, errbuf);
			net = 0;
			mask = 0;
		}

		handle = pcap_open_live(interface, MTU, 1, -1, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Erreur ouverture de %s: %s\n", interface, errbuf);
			//Si erreur de l'ouverture lister les interfaces
			pcap_if_t *alldevs;
			pcap_if_t *d;
			if (pcap_findalldevs(&alldevs, errbuf) == -1)
		    {
		        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		        exit(1);
		    }
		    printf("\nListe de toutes les interfaces:\n\n");
		    for(d=alldevs; d; d=d->next)
		    {
		        printf("%d %s\n",i++, d->name);
		        
		    }
			exit(EXIT_FAILURE);
		}
	}

	//Si présence de l'option fichier changement du handle
	if(o){
		printf("Filename: %s \n", filename);
		handle = pcap_open_offline(filename, errbuf);
		if (handle == NULL) {
		fprintf(stderr, "Erreur ouverture de %s: %s\n", filename, errbuf);
		exit(EXIT_FAILURE);
		}	
	}


	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", interface);
		exit(EXIT_FAILURE);
	}

	
	//Si présence de filtre
	if(f){
	// compiler le filter 
		if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
			fprintf(stderr, "Error pcap_compile sur %s: %s\n",filter, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}


		//Mettre le filter
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",filter, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}

	//passage de verb en argument pour callback, -1 infinite loop
	pcap_loop(handle, -1, callback, verb);

	
	//On free le bfp_prog si choix de filtre
	if(f){
		pcap_freecode(&fp);
	}
	pcap_close(handle);

	printf("\nFin.\n");





	return 0;
}