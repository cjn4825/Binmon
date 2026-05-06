#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "../include/protocol.h"

static void create_frame(void *ether_loc){
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

static void create_packet(void *pack_loc){
    struct iphdr *ip = (struct iphdr *)pack_loc;

    ip->saddr = SRC; // localhost...not sure if this is right
    ip->daddr = DST;
    ip->protocol = IPPROTO_UDP; // again not right probably
}

struct packet_header* binmon_header(void *header_loc){
    struct packet_header *ph = (struct packet_header*)header_loc;

    // init this better

    ph->magic_number = MAGIC_NUMBER;
    ph->version = VERSION;

    return ph;
}

void create_headers(void *offset){
    create_frame(offset);
    create_packet(offset + sizeof(struct ether_header));
}
