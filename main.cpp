#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print2hex(u_char* print, int print_len){
    for(int i=0; i<print_len; i++)
        printf("%02x ", print[i]);
}

void print_ip(iphdr* ipheader){
    printf("\nS-IP: %s\n", inet_ntoa(*(in_addr*)&ipheader->saddr));
    printf("D-IP: %s\n", inet_ntoa(*(in_addr*)&ipheader->daddr));
}

void print_port(tcphdr* tcpheader){
    printf("S-PORT: %d\n", ntohs(tcpheader->th_sport));
    printf("D-PORT: %d\n", ntohs(tcpheader->th_dport));
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("\n\n[+] %d bytes packet captured\n", header->caplen);

    ether_header* ethernet = (ether_header*) packet;
    printf("S_MAC: ");
    print2hex(ethernet->ether_dhost, ETHER_ADDR_LEN);
    printf("\nD_MAC: ");
    print2hex(ethernet->ether_shost, ETHER_ADDR_LEN);

    if(ntohs(ethernet->ether_type) == 2048)
    {
        iphdr* ipheader = (iphdr*)(packet+sizeof(ether_header));
        print_ip(ipheader);

        if(ipheader->protocol == 6){
            tcphdr* tcpheader = (tcphdr*)(packet+sizeof(ether_header)+sizeof(iphdr));
            print_port(tcpheader);

            if(tcpheader->psh == 1){
                uint8_t tcphdr_size = tcpheader->th_off * 4;
                u_char* tcpdata = (u_char *)(packet + sizeof(ether_header) + sizeof(iphdr) + tcphdr_size);
                uint32_t tcpdata_size= ipheader->tot_len - (sizeof(iphdr) + tcphdr_size);

                printf("TCP Data: ");
                if (tcphdr_size>10)
                    print2hex(tcpdata, 10);
                else
                    print2hex(tcpdata, tcpdata_size);
                printf("\n");
            }
        }
        else if(ipheader->protocol == 17){
            //UDP Protocol
        }
    }
    else if(ntohs(ethernet->ether_type) == 2054){
	    //ARP Protocol
    }

  }

  pcap_close(handle);
  return 0;
}
