#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

typedef struct ethhdr ethhdr;
typedef struct ip iphdr;


/* Looking for the first lucky packet captured */

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    ethhdr *eth = (ethhdr *) bytes;
    if (ntohs(eth->h_proto) == ETH_P_IP)
    {
        iphdr *ip = (iphdr *) (bytes + sizeof(ethhdr));
        if (ip->ip_p == IPPROTO_ICMP)
        {
            printf("Found ICMP packet: \n");
            printf("    From: %s\n", inet_ntoa(ip->ip_src));
            printf("    To: %s\n", inet_ntoa(ip->ip_dst));
        }
    }

}

int main(int argc, char** argv)
{
    pcap_t *hd;

    if (argc < 2)
    {
        printf("Please provide the interface name!\n");
        return 1;
    }

    char errbuffer[PCAP_ERRBUF_SIZE];

    hd = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuffer);

    if (!hd)
    {
        printf("Error msg: %s\n", errbuffer);
        return 1;
    }

    struct bpf_program bpf_p;

    char *filter_exp = "ip proto icmp";

    pcap_compile(hd, &bpf_p, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(hd, &bpf_p);

    pcap_loop(hd, 100, packet_handler, NULL);

    pcap_close(hd);
    return 0;

}