#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "compdetect_common.h"


void set_default(config_t* config)
{
    config->wait_time = 15;
    config->tcp_port = 6666;
    config->udp_src_port = 9876;
    config->udp_dst_port = 8765;
    config->udp_packet_ttl = 255;
    config->udp_packet_num = 6000;
    config->udp_packet_size = 1000;
    strcpy(config->server_addr, "");
    config->tcp_head_syn_port = 0;
    config->tcp_tail_syn_port = 0;
    return;
}

int load_config(char* fpath, config_t* config)
{
    FILE* fp;
    char buf[8192];

    set_default(config);

    if (!(fp = fopen(fpath, "r"))) {
        // return 0;
        return -1;
    }

    // TODO:
    while (fgets(buf, sizeof(buf), fp)) {
        size_t len = strlen(buf);
        buf[len] = 0;
        char* pos = strchr(buf, '=');
        if (!pos) {
            continue;
        }

        *pos = 0;
        char* key = buf;
        char* value = pos + 1;
        if (strcmp(key, "wait_time") == 0) {
            config->wait_time = atoi(value);
        } else if (strcmp(key, "tcp_port") == 0) {
            config->tcp_port = atoi(value);
        } else if (strcmp(key, "udp_src_port") == 0) {
            config->udp_src_port = atoi(value);
        } else if (strcmp(key, "udp_dst_port") == 0) {
            config->udp_dst_port = atoi(value);
        } else if (strcmp(key, "udp_packet_ttl") == 0) {
            config->udp_packet_ttl = atoi(value);
        } else if (strcmp(key, "udp_packet_num") == 0) {
            config->udp_packet_num = atoi(value);
        } else if (strcmp(key, "udp_packet_size") == 0) {
            config->udp_packet_size = atoi(value);
        } else if (strcmp(key, "tcp_head_syn_port") == 0) {
            config->tcp_head_syn_port = atoi(value);
        } else if (strcmp(key, "tcp_tail_syn_port") == 0) {
            config->tcp_tail_syn_port = atoi(value);
        } else if (strcmp(key, "server_addr") == 0) {
            strcpy(config->server_addr, value);
        }
    }

    if (config->wait_time <= 0 ||
        config->tcp_port <= 0 ||
        config->udp_src_port <= 0 || 
        config->udp_dst_port <= 0 ||
        config->udp_packet_size <= 0 ||
        config->udp_packet_num <= 0 ||
        config->udp_packet_ttl <= 0 ||
        config->tcp_head_syn_port <= 0 ||
        config->tcp_tail_syn_port <= 0 ||
        strlen(config->server_addr) <= 0) {
        fprintf(stderr, "invalid config file\n");
        fclose(fp);
        return -1;
    }



    fclose(fp);
    return 0;
}

int create_tcp_client(char* host, int port)
{
    struct sockaddr_in saddr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = inet_addr(host);

    if (connect(sockfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        perror("connect");
        return -1;
    }

    return sockfd;
}

int create_tcp_server(int port)
{
    struct sockaddr_in saddr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    int flag = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
        perror("setsockopt");
        return -1;
    }

    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        return -1;
    }

    if (listen(sockfd, 5) < 0) {
        perror("listen");
        return -1;
    }

    return sockfd;
}