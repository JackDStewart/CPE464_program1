#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "ethernet.h"

uint16_t ethernet(const unsigned char *packet) {
    ethernet_hdr_t eth_hdr;
    memcpy(&eth_hdr, packet, sizeof(eth_hdr));

    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr.dest[0], eth_hdr.dest[1], eth_hdr.dest[2],
           eth_hdr.dest[3], eth_hdr.dest[4], eth_hdr.dest[5]);
    printf("\t\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr.source[0], eth_hdr.source[1], eth_hdr.source[2],
           eth_hdr.source[3], eth_hdr.source[4], eth_hdr.source[5]);

    uint16_t eth_type = ntohs(eth_hdr.type);
    char *eth_type_string;
    switch (eth_type) {
        case 0x0800:  // IPv4
            eth_type_string = "IP";
            break;

        case 0x0806:
            eth_type_string = "ARP";
            break;

        default:
            eth_type_string = "unknown";
            break;
    }
    printf("\t\tType: %s\n\n", eth_type_string);
    return eth_type;
}
