#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "arp.h"

void arp(const unsigned char *packet) {
    if (packet == NULL) return;

    arp_hdr_t arp_hdr;
    memcpy(&arp_hdr, packet, sizeof(arp_hdr_t));

    // Interpret opcode
    uint16_t op = ntohs(arp_hdr.operation);
    const char *op_str = (op == 1) ? "Request" :
                         (op == 2) ? "Reply"   : "Unknown";

    // Build printable IPv4 addresses (bytes are already in network order)
    struct in_addr sender_ip, target_ip;
    memcpy(&sender_ip, arp_hdr.spa, sizeof(sender_ip));
    memcpy(&target_ip, arp_hdr.tpa, sizeof(target_ip));

    printf("\tARP header\n");
    printf("\t\tOpcode: %s\n", op_str);
    printf("\t\tSender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_hdr.sha[0], arp_hdr.sha[1], arp_hdr.sha[2], arp_hdr.sha[3], arp_hdr.sha[4], arp_hdr.sha[5]);
    printf("\t\tSender IP: %s\n", inet_ntoa(sender_ip));
    printf("\t\tTarget MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_hdr.tha[0], arp_hdr.tha[1], arp_hdr.tha[2], arp_hdr.tha[3], arp_hdr.tha[4], arp_hdr.tha[5]);
    printf("\t\tTarget IP: %s\n\n", inet_ntoa(target_ip));
}
