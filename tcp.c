#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "tcp.h"
#include "checksum.h"

uint16_t tcp_checksum(const unsigned char *packet);
char *tcp_port_name(uint16_t port);

void tcp(const unsigned char *packet) {
    if (packet == NULL) return;

    tcp_hdr_t tcp_hdr;
    memcpy(&tcp_hdr, packet, sizeof(tcp_hdr_t));

    char *src_port = tcp_port_name(ntohs(tcp_hdr.src_port));
    char *dst_port = tcp_port_name(ntohs(tcp_hdr.dst_port));
    uint32_t seq = ntohl(tcp_hdr.seq);
    uint32_t ack = ntohl(tcp_hdr.ack);

    unsigned int data_offset_bytes = (tcp_hdr.data_offset) * 4;
    if (data_offset_bytes < 20) data_offset_bytes = 20;

    int syn = (tcp_hdr.flags & 0x02) != 0;
    int rst = (tcp_hdr.flags & 0x04) != 0;
    int fin = (tcp_hdr.flags & 0x01) != 0;
    int ackf = (tcp_hdr.flags & 0x10) != 0;

    uint16_t window = ntohs(tcp_hdr.window);
    
    size_t seg_len = 0;
    extern uint16_t ip_total_length;
    extern unsigned int ip_header_len;
    if (ip_total_length && ip_header_len && ip_total_length >= ip_header_len) {
        seg_len = (size_t)ip_total_length - (size_t)ip_header_len;
    }

    printf("\tTCP Header\n");
    printf("\t\tSegment Length: %zu\n", seg_len);
    if (src_port) {
        printf("\t\tSource Port: %s\n", src_port);
    } else {
        printf("\t\tSource Port: %u\n", ntohs(tcp_hdr.src_port));
    }
    if (dst_port) {
        printf("\t\tDest Port: %s\n", dst_port);
    } else {
        printf("\t\tDest Port: %u\n", ntohs(tcp_hdr.dst_port));
    }
    printf("\t\tSequence Number: %u\n", seq);
    printf("\t\tACK Number: %u\n", ack);
    printf("\t\tData Offset (bytes): %u\n", data_offset_bytes);
    printf("\t\tSYN Flag: %s\n", syn ? "Yes" : "No");
    printf("\t\tRST Flag: %s\n", rst ? "Yes" : "No");
    printf("\t\tFIN Flag: %s\n", fin ? "Yes" : "No");
    printf("\t\tACK Flag: %s\n", ackf ? "Yes" : "No");
    printf("\t\tWindow Size: %u\n", window);

    uint16_t copy_checksum = tcp_checksum(packet);
    printf("\t\tChecksum: %s (0x%04x)\n\n", copy_checksum == tcp_hdr.checksum ? "Correct" : "Incorrect", ntohs(tcp_hdr.checksum));

}

uint16_t tcp_checksum(const unsigned char *packet) {
    
    // pseudo-header
    extern uint8_t source_ip[4], dest_ip[4];
    pseudo_tcp_hdr_t pseudo_hdr;
    memcpy(pseudo_hdr.source_ip, source_ip, 4);
    memcpy(pseudo_hdr.dest_ip, dest_ip, 4);

    extern uint16_t ip_total_length;
    extern unsigned int ip_header_len;

    pseudo_hdr.zero = 0;
    pseudo_hdr.protocol = 6; // TCP
    pseudo_hdr.seg_length = htons(ip_total_length - ip_header_len);

    // new buffer for pseudo-header + tcp header
    size_t buf_len = sizeof(pseudo_tcp_hdr_t) + ntohs(pseudo_hdr.seg_length);
    uint8_t buf[buf_len];

    memcpy(buf, &pseudo_hdr, sizeof(pseudo_tcp_hdr_t));
    memcpy(buf + sizeof(pseudo_tcp_hdr_t), packet, ntohs(pseudo_hdr.seg_length));

    // zero checksum field in new header 
    ((tcp_hdr_t *)(buf + sizeof(pseudo_tcp_hdr_t)))->checksum = 0;
    
    return (uint16_t)in_cksum((unsigned short*)buf, buf_len);
}

char *tcp_port_name(uint16_t port) {
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