#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

// ICMP header
typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;    
} icmp_hdr_t;

void icmp(const unsigned char *packet);

#endif
