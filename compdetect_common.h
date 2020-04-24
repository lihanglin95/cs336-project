#ifndef __COMPDETECT_COMMON_H__
#define __COMPDETECT_COMMON_H__


// Define some constants.
#define IP4_HDRLEN                  20         // IPv4 header length
#define UDP_HDRLEN                  8         // UDP header length, excludes data
#define IP4_ADDR_LEN                16
#define COMPRESSION_FOUND           "Compression detected!"
#define COMPRESSION_NOT_FOUND       "No compression was detected."

typedef struct {
    int tcp_port;
    int udp_src_port;
    int udp_dst_port;
    int wait_time; // Inter-Measurement Time (default value: 15 seconds)
    int udp_packet_ttl;
    int udp_packet_num;
    int udp_packet_size;
    int tcp_head_syn_port;
    int tcp_tail_syn_port;
    char server_addr[IP4_ADDR_LEN];
} config_t;

int load_config(char* fpath, config_t* config);

int create_tcp_client(char* host, int port);

int create_tcp_server(int port);


#endif // __COMPDETECT_COMMON_H__