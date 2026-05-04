#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "../include/protocol.h"

static inline void create_frame(void *ether_loc){
    // set mac address by grabbing it from host...for now hardcode an example
    struct ether_header *eth = (struct ether_header *)ether_loc;

    // find beter way to do this
    eth->ether_shost[0] = 0x00;
    eth->ether_shost[1] = 0x15;
    eth->ether_shost[2] = 0x5d;
    eth->ether_shost[3] = 0x69;
    eth->ether_shost[4] = 0xfe;
    eth->ether_shost[5] = 0x9b;

    eth->ether_dhost[0] = 0x00;
    eth->ether_dhost[1] = 0x15;
    eth->ether_dhost[2] = 0x5d;
    eth->ether_dhost[3] = 0x69;
    eth->ether_dhost[4] = 0xfe;
    eth->ether_dhost[5] = 0x9b;

    eth->ether_type = htons(ETH_P_IP); // see if right

}

//temp macro put in headerfile... or just use the one in the oher one and convert...
#define SRC 127001
#define DST 127001

static inline void create_packet(void *pack_loc){
    struct iphdr *ip = (struct iphdr *)pack_loc;

    ip->saddr = SRC; // localhost...not sure if this is right
    ip->daddr = DST;
    ip->protocol = IPPROTO_UDP; // again not right probably
}

void* create_binmon_header(void *header_loc){
    struct packet_header *ph = (struct packet_header*)header_loc;

    ph->magic_number = MAGIC_NUMBER;
    ph->packet_type = PACKET_TYPE;
    ph->time_stamp = // helper funtion in utils to get time
    ph->payload_length += // loop through all types and get tlv values? or is it fixed size?
                          // do i even need the lenght?
    ph->sequence++; // do i need this either? am i using udp or tcp?
    ph->crc = 0; //temp not sure if i need this here or within the actual headers
    ph->version = VERSION;

    return 0;
}

void* create_headers(void *area){

    create_frame(area);
    area += sizeof(struct ether_header);

    create_packet(area);
    area += sizeof(struct ether_header);

    create_binmon_header(area);

    return area;
}
