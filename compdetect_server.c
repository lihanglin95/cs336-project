#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "compdetect_common.h"


int main(int argc, char* argv[])
{
    int i;
    char* packet;
    config_t config;
    struct timeval beg, end;
    int delta_high, delta_low;
    int sockfd_tcp, sockfd_udp;
    struct sockaddr_in udp_addr, udp_saddr;

    if (argc < 2) {
        fprintf(stdout, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (load_config(argv[1], &config) < 0) {
        exit(EXIT_FAILURE);
    }

    if ((sockfd_tcp = create_tcp_server(config.tcp_port)) < 0) {
        exit(EXIT_FAILURE);
    }

    while (1) {
        int client_sockfd = accept(sockfd_tcp, NULL, NULL);
        if (client_sockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        if (read(client_sockfd, &config, sizeof(config)) != sizeof(config)) {
            perror("read");
            close(client_sockfd);
            continue;
        }

        break;
    }

    if ((sockfd_udp = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    udp_saddr.sin_family = AF_INET;
    udp_saddr.sin_port = htons(config.udp_dst_port);
    udp_saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd_udp, (struct sockaddr*)&udp_saddr, sizeof(udp_saddr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    int recv_buf_size = config.udp_packet_num * config.udp_packet_size * 2;
    if (setsockopt(sockfd_udp, SOL_SOCKET, SO_RCVBUF,
        (char*)&recv_buf_size, sizeof(recv_buf_size)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }


    packet = (char*)malloc(config.udp_packet_size);
    for (i=0; i<config.udp_packet_num; ++i) {
        if (recvfrom(sockfd_udp, packet, config.udp_packet_size, 0, NULL, NULL) != config.udp_packet_size) {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        if (i == 0) {
            gettimeofday(&beg, NULL);
        } else if (i == config.udp_packet_num - 1) {
            gettimeofday(&end, NULL);
        }

        // printf("recv low packet:%hu, i:%d\n", *((uint16_t*)packet), i);
    }

    delta_low = (end.tv_sec * 1000 * 1000 + end.tv_usec - beg.tv_sec * 1000 * 1000 - beg.tv_usec ) / 1000;
    printf("recv low packets cost %dms\n", delta_low);

    for (i=0; i<config.udp_packet_num; ++i) {
        if (recvfrom(sockfd_udp, packet, config.udp_packet_size, 0, NULL, NULL) != config.udp_packet_size) {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        if (i == 0) {
            gettimeofday(&beg, NULL);
        } else if (i == config.udp_packet_num - 1) {
            gettimeofday(&end, NULL);
        }

        // printf("recv high packet:%hu, i:%d\n", *((uint16_t*)packet), i);
    }

    delta_high = (end.tv_sec * 1000 * 1000 + end.tv_usec - beg.tv_sec * 1000 * 1000 - beg.tv_usec ) / 1000;
    printf("recv low packets cost %dms\n", delta_high);


    while (1) {
        int client_sockfd = accept(sockfd_tcp, NULL, NULL);
        if (client_sockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        int is_detected = 0;
        if (delta_high > delta_low + 100) {
            is_detected = 1;
        }

        write(client_sockfd, &is_detected, sizeof(is_detected));
        close(client_sockfd);
        break;
    }

    close(sockfd_tcp);
    close(sockfd_udp);

    return 0;
}