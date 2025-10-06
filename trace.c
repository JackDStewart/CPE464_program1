#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "checksum.h"


int main(int argc, char *argv[]){
    if (argc != 2) {
        fprintf(stderr, "Incorrect arg size: command=%s \n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_num = 0;
    printf("\n");
    while(1){
        int ret = pcap_next_ex(pcap, &header, &packet);
        if (ret == 1){
            packet_num++;
            printf("Packet number: %d  Packet Len: %u\n\n", packet_num, header->len);
            
            uint16_t eth_type = ethernet(packet);
            
            // eth types
            switch (eth_type) {
                case 0x0800:  // IPv4
                    ip(packet + sizeof(ethernet_hdr_t));
                    
                    // ip protocols
                    extern unsigned int ip_header_len;
                    extern uint8_t protocol_type;
                    switch (protocol_type) {
                        case 1:  // ICMP
                            icmp(packet + sizeof(ethernet_hdr_t) + ip_header_len);
                            break;
                        case 6:  // TCP
                            tcp(packet + sizeof(ethernet_hdr_t) + ip_header_len);
                            break;
                        case 17: // UDP
                            udp(packet + sizeof(ethernet_hdr_t) + ip_header_len);
                            break;
                    }
                    break;
                case 0x0806:  // ARP
                    arp(packet + sizeof(ethernet_hdr_t));
                    break;
            }

        }
        else if (ret == PCAP_ERROR_BREAK) {
            // end of file
            break;
        } 
        else if (ret == PCAP_ERROR) {
            fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(pcap));
            break;
        }
    }
    pcap_close(pcap);
    return 0;
}
