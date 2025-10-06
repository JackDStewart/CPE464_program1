#include <stdio.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include "icmp.h"

void icmp(const unsigned char *packet) {
    if (packet == NULL) return;

    icmp_hdr_t icmp_hdr;
    memcpy(&icmp_hdr, packet, sizeof(icmp_hdr_t));

    printf("\tICMP Header\n");
    printf("\t\tType: ");
    switch (icmp_hdr.type) {
        case 0: /* ICMP_ECHOREPLY */
            printf("Reply\n");
            break;
        case 8: /* ICMP_ECHO */
            printf("Request\n");
            break;
        default:
            printf("%d\n", icmp_hdr.type);
            break;
    }
    printf("\n");
}