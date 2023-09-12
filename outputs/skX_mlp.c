
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "bpf_helpers.h"

#define printk(fmt, ...)                                           \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

struct bpf_map_def SEC("maps") counter_pass = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") counter_drop = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

SEC("prog")
int xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u16 h_proto;
    __u64 nh_off = 0;
    __u32 index;

    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // parse ethernet header
    eth = data + nh_off;
    if ((void *)&eth[1] > data_end) {
        h_proto = 0;
    } else {
        h_proto = eth->h_proto;
    }
    nh_off = sizeof(*eth);

    if (h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // parse ipv4 header
    iph = data + nh_off;
    if ((void *)&iph[1] > data_end) {
        index = 0;
    } else {
        index = iph->protocol;
    }
    nh_off = sizeof(*iph);
    unsigned int ip_ihl = ntohl(iph->ihl);
    unsigned int ip_version = ntohl(iph->version);
    int ip_preference = IPTOS_PREC(iph->tos);
    int ip_dscp = IPTOS_TOS(iph->tos);
    uint16_t ip_total_length = ntohs(iph->tot_len);
    uint16_t ip_frag_offset = ntohs(iph->frag_off);
    uint8_t ip_ttl = iph->ttl;
    uint8_t ip_protocol = iph->protocol;

    // validate the length of data
    // eth+ipv4+tcp=54
    if (data_end < data + (54)) {
        return XDP_PASS;
    }

    // parse tcp header

    tcph = data + nh_off;
    uint16_t source_port = ntohs(tcph->source);
    uint16_t dest_port = ntohs(tcph->dest);
    unsigned int tcp_sequence_num = ntohl(tcph->seq);
    unsigned int tcp_ack_num = ntohl(tcph->ack_seq);
    uint16_t tcp_window_size = ntohs(tcph->window);
    uint16_t tcp_urgent_pointer = ntohs(tcph->urg_ptr);
    uint16_t tcp_cwr_flag = ntohs(tcph->cwr);
    uint16_t tcp_ece_flag = ntohs(tcph->ece);
    uint16_t tcp_urg_flag = ntohs(tcph->urg);
    uint16_t tcp_ack_flag = ntohs(tcph->ack);
    uint16_t tcp_psh_flag = ntohs(tcph->psh);
    uint16_t tcp_rst_flag = ntohs(tcph->rst);
    uint16_t tcp_syn_flag = ntohs(tcph->syn);
    uint16_t tcp_fin_flag = ntohs(tcph->fin);

    int y = 0;
    int h_0_0 = (int)ip_total_length;
    int h_0_1 = (int)ip_ttl;
    int h_0_2 = (int)ip_frag_offset;
    int h_0_3 = (int)ip_protocol;
    int h_0_4 = (int)ip_version;
    int h_0_5 = (int)tcp_syn_flag;
    int h_0_6 = (int)tcp_ack_flag;
    int h_0_7 = (int)tcp_fin_flag;
    int h_0_8 = (int)tcp_rst_flag;
    int h_0_9 = (int)tcp_window_size;

    int h_1_0 = -3036 + (0 * h_0_0) + (0 * h_0_1) + (0 * h_0_2) + (0 * h_0_3) + (0 * h_0_4) + (0 * h_0_5) + (0 * h_0_6) + (0 * h_0_7) + (0 * h_0_8) + (0 * h_0_9);
    h_1_0 = (0 > h_1_0)?0:h_1_0;
    h_1_0 = sdiv(h_1_0, 10000);
    int h_1_1 = 1258 + (-1610 * h_0_0) + (3064 * h_0_1) + (0 * h_0_2) + (-6092 * h_0_3) + (3342 * h_0_4) + (4053 * h_0_5) + (2482 * h_0_6) + (4201 * h_0_7) + (31846 * h_0_8) + (2590 * h_0_9);
    h_1_1 = (0 > h_1_1)?0:h_1_1;
    h_1_1 = sdiv(h_1_1, 10000);
    int h_1_2 = 18180 + (69 * h_0_0) + (-1073 * h_0_1) + (-279 * h_0_2) + (3366 * h_0_3) + (3769 * h_0_4) + (-3875 * h_0_5) + (-3881 * h_0_6) + (-3875 * h_0_7) + (-3881 * h_0_8) + (-3238 * h_0_9);
    h_1_2 = (0 > h_1_2)?0:h_1_2;
    h_1_2 = sdiv(h_1_2, 10000);
    int h_1_3 = -3430 + (0 * h_0_0) + (0 * h_0_1) + (0 * h_0_2) + (0 * h_0_3) + (0 * h_0_4) + (0 * h_0_5) + (0 * h_0_6) + (0 * h_0_7) + (0 * h_0_8) + (0 * h_0_9);
    h_1_3 = (0 > h_1_3)?0:h_1_3;
    h_1_3 = sdiv(h_1_3, 10000);
    int h_1_4 = 30299 + (-243 * h_0_0) + (-1300 * h_0_1) + (-837 * h_0_2) + (-501 * h_0_3) + (418 * h_0_4) + (-1075 * h_0_5) + (-1075 * h_0_6) + (-1075 * h_0_7) + (-1075 * h_0_8) + (-1075 * h_0_9);
    h_1_4 = (0 > h_1_4)?0:h_1_4;
    h_1_4 = sdiv(h_1_4, 10000);
    int h_1_5 = 27072 + (-251 * h_0_0) + (-911 * h_0_1) + (-584 * h_0_2) + (40 * h_0_3) + (723 * h_0_4) + (-1219 * h_0_5) + (-1219 * h_0_6) + (-1219 * h_0_7) + (-1219 * h_0_8) + (-1219 * h_0_9);
    h_1_5 = (0 > h_1_5)?0:h_1_5;
    h_1_5 = sdiv(h_1_5, 10000);
    int h_1_6 = -7775 + (-839 * h_0_0) + (-1036 * h_0_1) + (0 * h_0_2) + (239 * h_0_3) + (360 * h_0_4) + (172 * h_0_5) + (307 * h_0_6) + (0 * h_0_7) + (0 * h_0_8) + (4687 * h_0_9);
    h_1_6 = (0 > h_1_6)?0:h_1_6;
    h_1_6 = sdiv(h_1_6, 10000);
    int h_1_7 = 5627 + (-2207 * h_0_0) + (922 * h_0_1) + (34 * h_0_2) + (877 * h_0_3) + (-106 * h_0_4) + (-132 * h_0_5) + (-97 * h_0_6) + (38 * h_0_7) + (40 * h_0_8) + (875 * h_0_9);
    h_1_7 = (0 > h_1_7)?0:h_1_7;
    h_1_7 = sdiv(h_1_7, 10000);
    int h_1_8 = 27064 + (-253 * h_0_0) + (-199 * h_0_1) + (-39 * h_0_2) + (653 * h_0_3) + (880 * h_0_4) + (-1420 * h_0_5) + (-1418 * h_0_6) + (-1420 * h_0_7) + (-1418 * h_0_8) + (-1420 * h_0_9);
    h_1_8 = (0 > h_1_8)?0:h_1_8;
    h_1_8 = sdiv(h_1_8, 10000);
    int h_1_9 = 11626 + (-283 * h_0_0) + (-783 * h_0_1) + (-112 * h_0_2) + (-223 * h_0_3) + (-181 * h_0_4) + (-161 * h_0_5) + (-162 * h_0_6) + (-161 * h_0_7) + (-162 * h_0_8) + (-143 * h_0_9);
    h_1_9 = (0 > h_1_9)?0:h_1_9;
    h_1_9 = sdiv(h_1_9, 10000);

    int h_2_0 = -25691 + (0 * h_1_0) + (1848 * h_1_1) + (0 * h_1_2) + (0 * h_1_3) + (0 * h_1_4) + (0 * h_1_5) + (-590 * h_1_6) + (-5723 * h_1_7) + (3 * h_1_8) + (0 * h_1_9);
    h_2_0 = (0 > h_2_0)?0:h_2_0;
    h_2_0 = sdiv(h_2_0, 10000);
    int h_2_1 = 9955 + (0 * h_1_0) + (-3900 * h_1_1) + (3135 * h_1_2) + (0 * h_1_3) + (6547 * h_1_4) + (5461 * h_1_5) + (0 * h_1_6) + (201 * h_1_7) + (2681 * h_1_8) + (1387 * h_1_9);
    h_2_1 = (0 > h_2_1)?0:h_2_1;
    h_2_1 = sdiv(h_2_1, 10000);
    int h_2_2 = 952 + (0 * h_1_0) + (5706 * h_1_1) + (-356 * h_1_2) + (0 * h_1_3) + (-2334 * h_1_4) + (-1346 * h_1_5) + (-4605 * h_1_6) + (1156 * h_1_7) + (4498 * h_1_8) + (-364 * h_1_9);
    h_2_2 = (0 > h_2_2)?0:h_2_2;
    h_2_2 = sdiv(h_2_2, 10000);
    int h_2_3 = 1174 + (0 * h_1_0) + (3997 * h_1_1) + (-310 * h_1_2) + (0 * h_1_3) + (-1873 * h_1_4) + (-893 * h_1_5) + (-4264 * h_1_6) + (1527 * h_1_7) + (3066 * h_1_8) + (-283 * h_1_9);
    h_2_3 = (0 > h_2_3)?0:h_2_3;
    h_2_3 = sdiv(h_2_3, 10000);
    int h_2_4 = -4884 + (0 * h_1_0) + (0 * h_1_1) + (0 * h_1_2) + (0 * h_1_3) + (0 * h_1_4) + (0 * h_1_5) + (0 * h_1_6) + (0 * h_1_7) + (0 * h_1_8) + (0 * h_1_9);
    h_2_4 = (0 > h_2_4)?0:h_2_4;
    h_2_4 = sdiv(h_2_4, 10000);

    int h_3_0 = 59059 + (45 * h_2_0) + (-17871 * h_2_1) + (5160 * h_2_2) + (4572 * h_2_3) + (0 * h_2_4);
    y += h_3_0 > 0;


    __u32 key = 0;
    __u32 *val;

    if (y) {
        val = bpf_map_lookup_elem(&counter_drop, &key);
        if (val) {
            (*val)++;
            printk("Dropping IP: %x Count: %d\n", __constant_ntohl(iph->saddr),
                   *val);
        }
        return XDP_DROP;  // droping spam packets
                          // return XDP_PASS;
    }

    val = bpf_map_lookup_elem(&counter_pass, &key);
    if (val) {
        (*val)++;
        printk("Passing IP: %x Count: %d\n", __constant_ntohl(iph->saddr),
               *val);
    }

    return XDP_PASS;  // passing correct packets
}

char _license[] SEC("license") = "GPL";
