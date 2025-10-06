#ifndef ETHERNET
#define ETHERNET

#include <stdint.h>

// Ethernet header (14 bytes)
typedef struct __attribute__((packed)) {
    uint8_t  dest[6]; // Destination MAC address
    uint8_t  source[6]; // Source MAC address
    uint16_t type;
} ethernet_hdr_t;


uint16_t ethernet(const unsigned char *packet);

#endif
