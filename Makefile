CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -g -D_GNU_SOURCE

# list all your source files here
SRCS = trace.c ethernet.c arp.c ip.c icmp.c tcp.c udp.c checksum.c
OBJS = $(SRCS:.c=.o)

trace: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lpcap

clean:
	rm -f $(OBJS) trace
