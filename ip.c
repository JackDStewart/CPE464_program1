#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "ip.h"
#include "checksum.h"


uint16_t ip_total_length = 0;
unsigned int ip_header_len = 0;
uint8_t source_ip[4] = {0};
uint8_t dest_ip[4] = {0};
uint8_t protocol_type = 0;


void ip(const unsigned char *packet) {
    if (packet == NULL) return;

    ip_hdr_t hdr;
    /* copy from network packet into aligned object */
    memcpy(&hdr, packet, sizeof(hdr));

    ip_total_length = ntohs(hdr.total_length);
    ip_header_len = (hdr.ver_ihl & 0x0F) * 4;

    // protocols
    char *protocol;
    protocol_type = hdr.protocol;
    switch (hdr.protocol) {
        case 1:  
            protocol = "ICMP";
            break;
        case 6:  
            protocol = "TCP";
            break;
        case 17:
            protocol = "UDP";
            break;
        default:
            protocol = "Unknown";
    }
    // checksum
    unsigned char ip_hdr_copy[60];                  // max IPv4 header = 60
    memcpy(ip_hdr_copy, packet, ip_header_len);
    ip_hdr_copy[10] = 0; ip_hdr_copy[11] = 0;        // zero checksum field
    unsigned short copy_checksum = in_cksum((unsigned short*)ip_hdr_copy, ip_header_len);

    memcpy(source_ip, hdr.source, 4);
    memcpy(dest_ip, hdr.dest, 4);
    
    struct in_addr sender_ip, dst_ip;
    memcpy(&sender_ip, &hdr.source, sizeof(sender_ip));
    memcpy(&dst_ip, &hdr.dest, sizeof(dst_ip));

    printf("\tIP Header\n");
    printf("\t\tIP PDU Len: %u\n", ip_total_length);
    printf("\t\tHeader Len (bytes): %u\n", ip_header_len);
    printf("\t\tTTL: %u\n", hdr.ttl);
    printf("\t\tProtocol: %s\n", protocol);
    printf("\t\tChecksum: %s (0x%04x)\n", copy_checksum == hdr.checksum ? "Correct" : "Incorrect", ntohs(hdr.checksum));
    printf("\t\tSender IP: %s\n", inet_ntoa(sender_ip));
    printf("\t\tDest IP: %s\n\n", inet_ntoa(dst_ip));
}
