all: noob_pcap

noob_pcap: Final.o
	gcc -o noob_pcap Final.o -lpcap
Final.o: Final.c callback.h
	gcc -o Final.o -c Final.c -lpcap 
clean:
	rm -f *.o core
mrproper: clean
	rm -f noob_pcap