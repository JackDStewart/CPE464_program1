#ifndef UDP_HEADER
#define UDP_HEADER

#include <stdint.h>

// UDP header structure
typedef struct __attribute__((packed)) {
    uint16_t source_port;   // Source port
    uint16_t dest_port;     // Destination port
    uint16_t length;        // Length of UDP header and data
    uint16_t checksum;      // Checksum
} udp_hdr_t;

void udp(const unsigned char *packet);

#endif