#ifndef TCP_HEADER
#define TCP_HEADER

#include <stdint.h>

/* TCP header (basic fixed portion) */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t  reserved:4;
    uint8_t  data_offset:4;
#else
    uint8_t  data_offset:4;
    uint8_t  reserved:4;
#endif
    uint8_t  flags;             /* Control bits: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN */
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} tcp_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t  source_ip[4];
    uint8_t  dest_ip[4];
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t seg_length;
} pseudo_tcp_hdr_t;

void tcp(const unsigned char *packet);

#endif
