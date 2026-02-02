#include <iostream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <string>

void parse_EthernetHeader(unsigned char *buffer, bool full_output_enable){

    struct ethhdr *eth = (struct ethhdr *)buffer;

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