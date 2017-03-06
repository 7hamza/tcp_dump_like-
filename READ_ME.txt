Compilation
	make 
		généreation executable noob_pcap

Execution
	Capture sur interface : sudo ./noob_pcap -i <interface> -v <1-3> -f <filtre>
	Capture offline 	  : sudo ./noob_pcap -o <fichier> -v <1-3> -f <filtre>

	***/filtre optionnel
	***/verbosite, (interface ou fichier) : obligatoires	 
	***∕SI interface entrée non valide ->> Listing des interfaces existante
	***/Utilisation de la syntaxe pcap pour filtrer 

	exemple d'utilisasion : 
		sudo ./noob_pcap -i eth0 -v 1
		sudo ./noob_pcap -i eth0 -v 1 -f tcp
		sudo ./noob_pcap -o fichier -v 3 -f "tcp port 80"

	
		