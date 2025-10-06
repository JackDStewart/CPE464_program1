#ifndef ARP_HEADER
#define ARP_HEADER

#include <stdint.h>

/* ARP header (Ethernet + IPv4) */
typedef struct __attribute__((packed)) {
    uint16_t htype;     /* Hardware type */
    uint16_t ptype;     /* Protocol type */
    uint8_t  hlen;      /* Hardware address length */
    uint8_t  plen;      /* Protocol address length */
    uint16_t operation;      /* Operation */
    uint8_t  sha[6];    /* Sender hardware address */
    uint8_t  spa[4];    /* Sender protocol address */
    uint8_t  tha[6];    /* Target hardware address */
    uint8_t  tpa[4];    /* Target protocol address */
} arp_hdr_t;

void arp(const unsigned char *packet);

#endif
