#include "udp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

char *udp_port_name(uint16_t port);

void udp(const unsigned char *packet) {
    if (packet == NULL) return;

    udp_hdr_t udp_hdr;
    memcpy(&udp_hdr, packet, sizeof(udp_hdr_t));

    char *src_port = udp_port_name(ntohs(udp_hdr.source_port));
    char *dst_port = udp_port_name(ntohs(udp_hdr.dest_port));

    printf("\tUDP Header\n");
    if (src_port) {
        printf("\t\tSource Port: %s\n", src_port);
    } else {
        printf("\t\tSource Port: %u\n", ntohs(udp_hdr.source_port));
    }

    if (dst_port) {
        printf("\t\tDest Port: %s\n", dst_port);
    } else {
        printf("\t\tDest Port: %u\n", ntohs(udp_hdr.dest_port));
    }
    printf("\n");
}

char *udp_port_name(uint16_t port) {
    switch (port) {
        case 21: return "FTP";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        default: return NULL;
    }
}