#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>      // struct udphdr
#include <netinet/tcp.h>      // struct udphdr
#include "compdetect_common.h"

#define TCP_HDRLEN 20

int sockfd;
config_t config;
int rst_received = 0;
const char* ip_src = "192.168.1.6";
struct timeval first_rst_time, last_rst_time;

static int send_syn(int is_head);

static int send_udp_packets();

static void* recv_thread_routine(void* arg);

uint16_t checksum(uint16_t *addr, int len);

uint16_t tcp4_checksum(struct ip, struct tcphdr, uint8_t *, int);

uint16_t udp4_checksum(struct ip, struct udphdr, uint8_t*, int);



int main(int argc, char* argv[])
{
    // int sockfd;
    pthread_t recv_thread;
    struct timeval first_rst_time, second_rst_time;

    if (argc < 2) {
        fprintf(stdout, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (load_config(argv[1], &config) < 0) {
        exit(EXIT_FAILURE);
    }

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int send_buf_size = config.udp_packet_num * config.udp_packet_size * 2;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
        (char*)&send_buf_size, sizeof(send_buf_size)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    pthread_create(&recv_thread, NULL, recv_thread_routine, NULL);
    pthread_detach(recv_thread);

    send_syn(1);

    send_udp_packets();

    send_syn(0);

    sleep(10);

    if (rst_received != 2) {
        printf("%s\n", "Failed to detect due to insufficient information.");
    }

    return 0;
}

void* recv_thread_routine(void* arg)
{
    int n;
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(config.udp_src_port);
    saddr.sin_addr.s_addr = inet_addr(config.server_addr);
    void* packet = calloc(IP_MAXPACKET, 1);
    struct ip* iphdr = packet;
    while (1) {
        n = read(sockfd, iphdr, IP4_HDRLEN);
        fprintf(stderr, "read %d bytes\n", n);
        if (iphdr->ip_p == IPPROTO_TCP) {
            struct tcphdr* tcphdr = packet + IP4_HDRLEN;
            read(sockfd, tcphdr, sizeof(*tcphdr));
            if (tcphdr->rst) {
                if (rst_received == 0) {
                    gettimeofday(&first_rst_time, NULL);
                } else {
                    gettimeofday(&last_rst_time, NULL);
                    break;
                }
            }
        }
    }
}

int send_syn(int is_head_syn)
{
    int i, n;
    struct ip* iphdr;
    uint8_t ip_flags[4];
    struct tcphdr* tcphdr;
    size_t packet_len = 0;
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(is_head_syn ? config.tcp_head_syn_port : config.tcp_tail_syn_port);
    saddr.sin_addr.s_addr = inet_addr(config.server_addr);
    void* tcp_packet = calloc(IP_MAXPACKET, 1);
    
    
    iphdr = tcp_packet;
    iphdr->ip_v = 4;
    iphdr->ip_sum = 0;
    iphdr->ip_tos = 0;
    iphdr->ip_id = htons(0);
    iphdr->ip_p = IPPROTO_TCP;
    iphdr->ip_ttl = 255;
    iphdr->ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);
    inet_pton(AF_INET, ip_src, &(iphdr->ip_src));
    inet_pton(AF_INET, config.server_addr, &(iphdr->ip_dst));
    iphdr->ip_hl = IP4_HDRLEN / sizeof (uint32_t);
    iphdr->ip_len = htons(sizeof(*iphdr) + sizeof(*tcphdr) + 0);
    iphdr->ip_sum = checksum((uint16_t *)iphdr, IP4_HDRLEN);

    packet_len += IP4_HDRLEN;

    tcphdr = tcp_packet + sizeof(*iphdr);
    tcphdr->syn = 1;
    tcphdr->th_seq = 0;
    tcphdr->th_ack = htonl(1);
    tcphdr->th_off = TCP_HDRLEN / 4;
    tcphdr->th_win = htons(65535);
    tcphdr->th_sport = htons(config.udp_src_port);
    tcphdr->th_dport = htons(is_head_syn ? config.tcp_head_syn_port : config.tcp_tail_syn_port);
    tcphdr->th_sum = tcp4_checksum(*iphdr, *tcphdr, NULL, 0);
    packet_len += sizeof(*tcphdr);
    n = sendto(sockfd, tcp_packet, packet_len, 0, (struct sockaddr*)&saddr, sizeof(saddr));
    fprintf(stderr, "send_syn|n:%d, packet length:%lu\n", n, packet_len);
    return 0;
}

int send_udp_packets()
{
    int i, n;
    struct ip* iphdr;
    uint8_t ip_flags[4];
    struct udphdr* udphdr;
    size_t packet_len = 0;
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(config.udp_dst_port);
    saddr.sin_addr.s_addr = inet_addr(config.server_addr);
    void* udp_packet = calloc(IP_MAXPACKET, 1);

      // Zero (1 bit)
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 1;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;
    
    
    iphdr = udp_packet;
    iphdr->ip_v = 4;
    iphdr->ip_sum = 0;
    iphdr->ip_tos = 0;
    iphdr->ip_id = htons(0);
    iphdr->ip_p = IPPROTO_UDP;
    iphdr->ip_ttl = config.udp_packet_ttl;
    inet_pton(AF_INET, ip_src, &(iphdr->ip_src));
    inet_pton(AF_INET, config.server_addr, &(iphdr->ip_dst));
    iphdr->ip_hl = IP4_HDRLEN / sizeof (uint32_t);
    iphdr->ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);
    iphdr->ip_len = htons(sizeof(*iphdr) + sizeof(*udphdr) + config.udp_packet_size);
    iphdr->ip_sum = checksum((uint16_t *)iphdr, IP4_HDRLEN);

    packet_len = IP4_HDRLEN;

    udphdr = udp_packet + sizeof(*iphdr);
    char* data = udp_packet + sizeof(*iphdr) + sizeof(*udphdr);
    for (i=0; i<config.udp_packet_num; ++i) {
        *(uint16_t*)(data) = (uint16_t)(config.udp_packet_num - 1 - i);
        udphdr->source = htons(config.udp_src_port);
        udphdr->dest = htons(config.udp_dst_port);
        udphdr->len = htons(UDP_HDRLEN + config.udp_packet_size);
        udphdr->check = udp4_checksum(*iphdr, *udphdr, data, config.udp_packet_size);
        packet_len += UDP_HDRLEN;
        packet_len += config.udp_packet_size;
        // n = write(sockfd, udp_packet, packet_len);
        n = sendto(sockfd, udp_packet, packet_len, 0, (struct sockaddr*)&saddr, sizeof(saddr));
        // fprintf(stderr, "send_udp_packets|n:%d, packet length:%lu\n", n, packet_len);
        // sendto(scokfd, )
        packet_len = IP4_HDRLEN;
        usleep(200);
    }
    
    return 0;
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}


// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t
udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

uint16_t
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen)
{
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;
    int i;
 
    ptr = &buf[0];  // ptr points to beginning of buffer buf
 
    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
    ptr += sizeof (iphdr.ip_src.s_addr);
    chksumlen += sizeof (iphdr.ip_src.s_addr);
 
    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
    ptr += sizeof (iphdr.ip_dst.s_addr);
    chksumlen += sizeof (iphdr.ip_dst.s_addr);
 
    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;
 
    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
    ptr += sizeof (iphdr.ip_p);
    chksumlen += sizeof (iphdr.ip_p);
 
    // Copy TCP length to buf (16 bits)
    svalue = htons (sizeof (tcphdr) + payloadlen);
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    chksumlen += sizeof (svalue);
 
    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);
 
    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);
 
    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);
 
    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);
 
    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);
 
    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);
 
    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);
 
    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;
 
    // Copy urgent pointer to buf (16 bits)
    memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
    ptr += sizeof (tcphdr.th_urp);
    chksumlen += sizeof (tcphdr.th_urp);
 
    // Copy payload to buf
    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;
 
    // Pad to the next 16-bit boundary
    for (i=0; i<payloadlen%2; i++, ptr++) {
      *ptr = 0;
      ptr++;
      chksumlen++;
    }
 
    return checksum ((uint16_t *) buf, chksumlen);
}
