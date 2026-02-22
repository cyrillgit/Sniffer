// main.cpp
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

#include "functions.h"


int main(int argc, char* argv[]) {

    std::cout << argv[0] << std::endl;

    if (argc < 3){
        std::cout << "Usage format: ./Sniffer [num_of_packets] [full output: 0 or 1]" << std::endl;
        return 0;
    }

    int num_of_packets = std::stoi(argv[1]);
    bool full_output_enable = std::stoi(argv[2]);
    // TODO: add function to handle input properly, preventing bad input

    std::cout << "------------------Sniffer start------------------" << std::endl;

    // AF_PACKET - низкий уровень, видим заголовки Ethernet
    // SOCK_RAW - сырой сокет
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    std::cout << "Sniffer initialization success. Starting capture..." << std::endl;

    unsigned char buffer[65536];
    unsigned int num_of_packets_i = num_of_packets;
    do {
        // Читаем пакет
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, NULL, NULL);
        if (data_size < 0) {
            perror("Recvfrom error");
            return 1;
        }
        std::cout << "Packet size: " << std::dec << data_size << " bytes" << std::endl;

        struct ethhdr *ethernet_header_address = (struct ethhdr *)buffer;
        parse_EthernetHeader(ethernet_header_address, full_output_enable);

        struct iphdr* ip_header_address = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        uint16_t eth_protocol = ntohs(ethernet_header_address->h_proto); 
        if (eth_protocol == ETH_P_IP) { 
            // Если это IPv4 (0x0800), вызываем парсер L3
            parse_IP_Header(ip_header_address, full_output_enable);

            uint16_t ip_protocol = (uint16_t)ip_header_address->protocol;
            if (ip_protocol == IPPROTO_TCP) {
                // std::cout << "[TCP]" << std::endl;
                struct tcphdr *tcp_header_address = (struct tcphdr*)((char*)ip_header_address + sizeof(struct iphdr));
                parse_TCP_Header(tcp_header_address, full_output_enable);
            } else if (ip_protocol == IPPROTO_UDP) {
                std::cout << "[UDP]" << std::endl;
            }
            
        } else if (eth_protocol == ETH_P_ARP) {
            std::cout << "[ARP] This is an ARP packet (skipped)" << std::endl;
        } else if (eth_protocol == ETH_P_IPV6) {
            std::cout << "[IPv6] This is IPv6 (parser not implemented yet)" << std::endl;
        } else {
            std::cout << "[Unknown] Protocol ID: 0x" << std::hex << eth_protocol << std::endl;
        }
      
        num_of_packets_i--;
    } while(num_of_packets_i > 0);

    close(sock_raw);
    std::cout << "------------------Sniffer stop------------------" << std::endl;
    return 0;
}
