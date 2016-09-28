send_arp : send_arp.o
	gcc -o send_arp send_arp.o -lpcap

send-arp.o : send_arp.c
	gcc -c -o send_arp.o send_arp.c -lpcap

clean :
	rm -f *.o
	rm -f send_arp
