#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>

#define MAX_IPS 256

typedef struct {
    int total_packets;
    int tcp_count;
    int tcp_size;
    int udp_count;
    int udp_size;
    int icmp_count;
    int icmp_size;
    int ip_count;
    int ip_size;
    int other_count;
    int other_size;
    int src_ip_counts[MAX_IPS];
    int dst_ip_counts[MAX_IPS];
    pthread_mutex_t lock;
} packet_stats_t;

volatile int keep_running = 1;

void int_handler(int dummy) {
    keep_running = 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    packet_stats_t *stats = (packet_stats_t *)user_data;
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet headers
    struct udphdr *udp_header = NULL;
    struct tcphdr *tcp_header = NULL;
    const char *protocol_name = "Other";

    pthread_mutex_lock(&stats->lock);

    stats->total_packets++;
    int packet_size = pkthdr->len;

    unsigned int src_ip = ntohl(ip_header->ip_src.s_addr);
    unsigned int dst_ip = ntohl(ip_header->ip_dst.s_addr);
    unsigned int src_ip_index = src_ip % MAX_IPS;
    unsigned int dst_ip_index = dst_ip % MAX_IPS;

    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            stats->tcp_count++;
            stats->tcp_size += packet_size;
            tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);
            protocol_name = "TCP";
            break;
        case IPPROTO_UDP:
            stats->udp_count++;
            stats->udp_size += packet_size;
            udp_header = (struct udphdr *)(packet + 14 + ip_header->ip_hl * 4);
            protocol_name = "UDP";
            break;
        case IPPROTO_ICMP:
            stats->icmp_count++;
            stats->icmp_size += packet_size;
            protocol_name = "ICMP";
            break;
        case IPPROTO_IP:
            stats->ip_count++;
            stats->ip_size += packet_size;
            protocol_name = "IP";
            break;
        default:
            stats->other_count++;
            stats->other_size += packet_size;
            break;
    }

    // Increment IP counts
    stats->src_ip_counts[src_ip_index]++;
    stats->dst_ip_counts[dst_ip_index]++;

    pthread_mutex_unlock(&stats->lock);

    // Log packet details
    FILE *packet_log_file = fopen("packet_logs.txt", "a");
    if (packet_log_file == NULL) {
        perror("Error opening packet log file");
        return;
    }

    fprintf(packet_log_file, "%s Packet Details:\n", protocol_name);
    fprintf(packet_log_file, "----------------\n");

    // Write Ethernet Header
    fprintf(packet_log_file, "Ethernet Header\n");
    fprintf(packet_log_file, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    fprintf(packet_log_file, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    fprintf(packet_log_file, "   |-Protocol            : %u \n", ip_header->ip_p);

    // Write IP Header
    fprintf(packet_log_file, "\nIP Header\n");
    fprintf(packet_log_file, "   |-IP Version        : %d\n", (int)ip_header->ip_v);
    fprintf(packet_log_file, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (int)ip_header->ip_hl, ((int)(ip_header->ip_hl)) * 4);
    fprintf(packet_log_file, "   |-Type Of Service   : %d\n", (int)ip_header->ip_tos);
    fprintf(packet_log_file, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(ip_header->ip_len));
    fprintf(packet_log_file, "   |-Identification    : %d\n", ntohs(ip_header->ip_id));
    fprintf(packet_log_file, "   |-TTL      : %d\n", (int)ip_header->ip_ttl);
    fprintf(packet_log_file, "   |-Protocol : %d\n", (int)ip_header->ip_p);
    fprintf(packet_log_file, "   |-Checksum : %d\n", ntohs(ip_header->ip_sum));
    fprintf(packet_log_file, "   |-Source IP        : %s\n", inet_ntoa(ip_header->ip_src));
    fprintf(packet_log_file, "   |-Destination IP   : %s\n", inet_ntoa(ip_header->ip_dst));

    // Write TCP Header if applicable
    if (tcp_header != NULL) {
        fprintf(packet_log_file, "\nTCP Header\n");
        fprintf(packet_log_file, "   |-Source Port      : %u\n", ntohs(tcp_header->source));
        fprintf(packet_log_file, "   |-Destination Port : %u\n", ntohs(tcp_header->dest));
        fprintf(packet_log_file, "   |-Sequence Number    : %u\n", ntohl(tcp_header->seq));
        fprintf(packet_log_file, "   |-Acknowledge Number : %u\n", ntohl(tcp_header->ack_seq));
        fprintf(packet_log_file, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcp_header->doff, (unsigned int)tcp_header->doff * 4);
        fprintf(packet_log_file, "   |-Urgent Flag          : %d\n", (unsigned int)tcp_header->urg);
        fprintf(packet_log_file, "   |-Acknowledgement Flag : %d\n", (unsigned int)tcp_header->ack);
        fprintf(packet_log_file, "   |-Push Flag            : %d\n", (unsigned int)tcp_header->psh);
        fprintf(packet_log_file, "   |-Reset Flag           : %d\n", (unsigned int)tcp_header->rst);
        fprintf(packet_log_file, "   |-Synchronise Flag     : %d\n", (unsigned int)tcp_header->syn);
        fprintf(packet_log_file, "   |-Finish Flag          : %d\n", (unsigned int)tcp_header->fin);
        fprintf(packet_log_file, "   |-Window         : %d\n", ntohs(tcp_header->window));
        fprintf(packet_log_file, "   |-Checksum       : %d\n", ntohs(tcp_header->check));
        fprintf(packet_log_file, "   |-Urgent Pointer : %d\n", tcp_header->urg_ptr);
    }

    // Write UDP Header if applicable
    if (udp_header != NULL) {
        fprintf(packet_log_file, "\nUDP Header\n");
        fprintf(packet_log_file, "   |-Source Port      : %u\n", ntohs(udp_header->source));
        fprintf(packet_log_file, "   |-Destination Port : %u\n", ntohs(udp_header->dest));
        fprintf(packet_log_file, "   |-UDP Length       : %u\n", ntohs(udp_header->len));
        fprintf(packet_log_file, "   |-UDP Checksum     : %u\n", ntohs(udp_header->check));
    }

    // Write Data Payload
    fprintf(packet_log_file, "\nData Payload\n");
    for (int i = 0; i < pkthdr->len; i++) {
        fprintf(packet_log_file, "%02X ", packet[i]);
        if ((i + 1) % 16 == 0)
            fprintf(packet_log_file, "\n");
    }

    fprintf(packet_log_file, "\n\n");

    fclose(packet_log_file);
}

void capture_packets(const char *interface, packet_stats_t *stats) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, error_buffer);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, error_buffer);
        exit(EXIT_FAILURE);
    }

    while (keep_running) {
        pcap_dispatch(handle, -1, packet_handler, (u_char *)stats);
        sleep(1);
    }

    pcap_close(handle);
}

void write_stats_to_file(packet_stats_t *stats) {
    const char *filename = "packet_stats.txt";

    while (keep_running) {
        sleep(3);
                pthread_mutex_lock(&stats->lock);

        FILE *file = fopen(filename, "a");
        if (file == NULL) {
            perror("Error opening file");
            pthread_mutex_unlock(&stats->lock);
            continue;
        }

        fprintf(file, "Protocol Statistics:\n");
        fprintf(file, "-------------------\n");
        fprintf(file, "Total Packets: %d\n", stats->total_packets);
        fprintf(file, "TCP Packets: %d\n", stats->tcp_count);
        fprintf(file, "TCP Size: %d bytes\n", stats->tcp_size);
        fprintf(file, "UDP Packets: %d\n", stats->udp_count);
        fprintf(file, "UDP Size: %d bytes\n", stats->udp_size);
        fprintf(file, "ICMP Packets: %d\n", stats->icmp_count);
        fprintf(file, "ICMP Size: %d bytes\n", stats->icmp_size);
        fprintf(file, "IP Packets: %d\n", stats->ip_count);
        fprintf(file, "IP Size: %d bytes\n", stats->ip_size);
        fprintf(file, "Other Packets: %d\n", stats->other_count);
        fprintf(file, "Other Size: %d bytes\n", stats->other_size);
        fprintf(file, "Source IP Counts:\n");
        for (int i = 0; i < MAX_IPS; i++) {
            if (stats->src_ip_counts[i] > 0) {
                struct in_addr ip_addr;
                ip_addr.s_addr = htonl(i);
                fprintf(file, "    %s: %d\n", inet_ntoa(ip_addr), stats->src_ip_counts[i]);
            }
        }
        fprintf(file, "Destination IP Counts:\n");
        for (int i = 0; i < MAX_IPS; i++) {
            if (stats->dst_ip_counts[i] > 0) {
                struct in_addr ip_addr;
                ip_addr.s_addr = htonl(i);
                fprintf(file, "    %s: %d\n", inet_ntoa(ip_addr), stats->dst_ip_counts[i]);
            }
        }

        fclose(file);

        pthread_mutex_unlock(&stats->lock);
    }
}

int main(int argc, char *argv[]) {
    int opt;
    char *interface = "ens160";

    signal(SIGINT, int_handler);

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-i interface]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    packet_stats_t stats = {0};
    pthread_mutex_init(&stats.lock, NULL);

    pthread_t writer_thread;
    if (pthread_create(&writer_thread, NULL, (void *(*)(void *))write_stats_to_file, &stats) != 0) {
        fprintf(stderr, "Error creating writer thread\n");
        exit(EXIT_FAILURE);
    }

    capture_packets(interface, &stats);

    pthread_join(writer_thread, NULL);
    pthread_mutex_destroy(&stats.lock);

    return 0;
}