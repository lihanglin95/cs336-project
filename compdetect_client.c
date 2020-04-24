#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "compdetect_common.h"


int main(int argc, char* argv[])
{
    int i, j;
    int flag; 
    char* packet;
    int random_fd;
    config_t config;
    int sockfd_tcp, sockfd_udp;
    struct sockaddr_in udp_addr, udp_saddr;

    if (argc < 2) {
        fprintf(stdout, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (load_config(argv[1], &config) < 0) {
        fprintf(stderr, "read config failed\n");
        exit(EXIT_FAILURE);
    }

    if ((sockfd_tcp = create_tcp_client(config.server_addr, config.tcp_port)) < 0) {
        exit(EXIT_FAILURE);
    }

    if (write(sockfd_tcp, &config, sizeof(config)) != sizeof(config)) {
        perror("send");
        close(sockfd_tcp);
        exit(EXIT_FAILURE);
    }

    close(sockfd_tcp);

    sockfd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_udp < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = htons(config.udp_src_port);
    udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd_udp, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    int send_buf_size = config.udp_packet_num * config.udp_packet_size * 2;
    if (setsockopt(sockfd_udp, SOL_SOCKET, SO_SNDBUF,
        (char*)&send_buf_size, sizeof(send_buf_size)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    flag = IP_PMTUDISC_DO;
    setsockopt(sockfd_udp, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag));

    udp_saddr.sin_family = AF_INET;
    udp_saddr.sin_port = htons(config.udp_dst_port);
    udp_saddr.sin_addr.s_addr = inet_addr(config.server_addr);

    packet = (char*)calloc(config.udp_packet_size, sizeof(char));
    for (i=0; i<config.udp_packet_num; ++i) {
        *((uint16_t*)packet) = (uint16_t)(i);
        if (sendto(sockfd_udp, packet, config.udp_packet_size, 0, 
            (struct sockaddr*)&(udp_saddr), sizeof(udp_saddr)) != config.udp_packet_size) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }

        usleep(200);

        // printf("send low packet:%hu\n", i);
    }

    sleep(config.wait_time);

    random_fd = open("/dev/urandom", O_RDONLY);
    for (j=sizeof(uint16_t); j<config.udp_packet_size; ++j) {
        read(random_fd, &(packet[j]), sizeof(char));
    }
    for (i=0; i<config.udp_packet_num; ++i) {
        *((uint16_t*)packet) = (uint16_t)(i);
        if (sendto(sockfd_udp, packet, config.udp_packet_size, 0, 
            (struct sockaddr*)&(udp_saddr), sizeof(udp_saddr)) != config.udp_packet_size) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }
        usleep(200);
        // printf("send high packet:%hu\n", i);
    }

    if ((sockfd_tcp = create_tcp_client(config.server_addr, config.tcp_port)) < 0) {
        exit(EXIT_FAILURE);
    }

    int is_detected = 0;
    if (read(sockfd_tcp, &is_detected, sizeof(is_detected)) < 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    printf("%s\n", (is_detected ? COMPRESSION_FOUND : COMPRESSION_NOT_FOUND));

    close(sockfd_tcp);
    close(sockfd_udp);

    return 0;
}