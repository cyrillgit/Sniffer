// main.cpp
#include <iostream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <string>

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
    // htons(ETH_P_ALL) - ловим все протоколы (IP, ARP и т.д.)
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(3)); // 3 - это ETH_P_ALL

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

        parse_EthernetHeader(buffer, full_output_enable);
        
        num_of_packets_i--;
    } while(num_of_packets_i > 0);

    close(sock_raw);
    std::cout << "------------------Sniffer stop------------------" << std::endl;
    return 0;
}
