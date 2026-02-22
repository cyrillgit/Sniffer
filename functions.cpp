#include <string>
#include <iostream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void parse_EthernetHeader(struct ethhdr *eth, bool full_output_enable){

    // struct ethhdr *eth = (struct ethhdr *)buffer;

    if(full_output_enable) {
        std::cout << "[ETH HDR] destination MAC: ";
        for(int i = 0; i < ETH_ALEN; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') <<  (static_cast<int>(eth->h_dest[i]) & 0xff);
            if (i < ETH_ALEN - 1) std::cout << ":";
        }
        
        std::cout << ", source MAC:";
        for(int i = 0; i < ETH_ALEN; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(eth->h_source[i]) & 0xff);
            if (i < ETH_ALEN - 1) std::cout << ":";
        }

        std::cout<< ", protocol ID:" << std::dec << ntohs(eth->h_proto) << std::endl;
    }
}

void parse_IP_Header(struct iphdr *buffer, bool full_output_enable){

    struct iphdr *ip = (struct iphdr *)buffer;
    uint32_t saddr = ntohl(ip->saddr);
    uint32_t daddr = ntohl(ip->daddr);

    if(full_output_enable) {
        std::cout << "[IP HDR]: ";

        std::cout << "src IP: "
        << ((saddr >> 24) & 0xFF)
        << "." << ((saddr >> 16) & 0xFF)
        << "." << ((saddr >> 8) & 0xFF)
        << "." << (saddr & 0xFF);

        std::cout << ", dest IP: "
        << ((daddr >> 24) & 0xFF)
        << "." << ((daddr >> 16) & 0xFF)
        << "." << ((daddr >> 8) & 0xFF)
        << "." << (daddr & 0xFF);

        std::cout << ", protocol: "
        << (uint16_t)ip->protocol;
        // TODO: make better protocol output

        // std::cout << ", ttl: "
        // << (uint16_t)ip->ttl;

        std::cout << std::endl;
    }
}

void parse_TCP_Header(struct tcphdr *buffer, bool full_output_enable){

    struct tcphdr *tcp_header = (struct tcphdr *)buffer;

    if(full_output_enable) {
        std::cout << "[TCP HDR]: ";

        std::cout << "src port: "
        << ntohs(tcp_header->th_sport)
        << ", dest port: "
        << ntohs(tcp_header->th_dport)
        << std::endl;

        // TODO

    }
}