#ifndef FUNCTIONS_H
#define FUNCTIONS_H

void parse_EthernetHeader(struct ethhdr *buffer, bool full_output_enable);
void parse_IP_Header(struct iphdr *buffer, bool full_output_enable);
void parse_TCP_Header(struct tcphdr *buffer, bool full_output_enable);

#endif