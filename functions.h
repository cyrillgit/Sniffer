#ifndef FUNCTIONS_H
#define FUNCTIONS_H

void parse_EthernetHeader(struct ethhdr *buffer, bool full_output_enable);
void parse_IP_Header(unsigned char *buffer, bool full_output_enable);

#endif