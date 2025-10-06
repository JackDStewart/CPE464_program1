#ifndef IP_HEADER
#define IP_HEADER

#include <stdint.h>

/* IPv4 header (minimal fields) */
typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;           /* Version (4 bits) + IHL (4 bits) */
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragoffset;  /* Flags + Fragment offset */
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t source[4];
    uint8_t dest[4];
} ip_hdr_t;

/* optional globals other modules referenced */
extern uint16_t ip_total_length;
extern unsigned int ip_header_len;
extern uint8_t source_ip[4];
extern uint8_t dest_ip[4];
extern uint8_t protocol_type;

void ip(const unsigned char *packet);

#endif
