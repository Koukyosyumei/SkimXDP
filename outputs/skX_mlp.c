
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

    int y = 1;
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

    int h_1_0 = 13349 + (-559 * h_0_0) + (-1494 * h_0_1) + (86 * h_0_2) + (8360 * h_0_3) + (17536 * h_0_4) + (-1327 * h_0_5) + (7771 * h_0_6) + (-1106 * h_0_7) + (-530 * h_0_8) + (-503 * h_0_9);
    h_1_0 = sdiv(h_1_0, 10000);
    int h_1_1 = -30272 + (-1045 * h_0_0) + (-145 * h_0_1) + (546 * h_0_2) + (-25661 * h_0_3) + (-23377 * h_0_4) + (-122 * h_0_5) + (-19537 * h_0_6) + (-1021 * h_0_7) + (712 * h_0_8) + (957 * h_0_9);
    h_1_1 = sdiv(h_1_1, 10000);
    int h_1_2 = 12207 + (5853 * h_0_0) + (1328 * h_0_1) + (-54 * h_0_2) + (3780 * h_0_3) + (1026 * h_0_4) + (107 * h_0_5) + (207 * h_0_6) + (141 * h_0_7) + (-112 * h_0_8) + (70 * h_0_9);
    h_1_2 = sdiv(h_1_2, 10000);
    int h_1_3 = -18000 + (-1972 * h_0_0) + (-4155 * h_0_1) + (-231 * h_0_2) + (-7484 * h_0_3) + (-4371 * h_0_4) + (-825 * h_0_5) + (385 * h_0_6) + (-432 * h_0_7) + (-116 * h_0_8) + (-683 * h_0_9);
    h_1_3 = sdiv(h_1_3, 10000);
    int h_1_4 = -18389 + (-6301 * h_0_0) + (2066 * h_0_1) + (106 * h_0_2) + (-13973 * h_0_3) + (-18650 * h_0_4) + (1210 * h_0_5) + (-8449 * h_0_6) + (489 * h_0_7) + (-273 * h_0_8) + (330 * h_0_9);
    h_1_4 = sdiv(h_1_4, 10000);
    int h_1_5 = 10998 + (339 * h_0_0) + (8760 * h_0_1) + (-43 * h_0_2) + (4168 * h_0_3) + (3557 * h_0_4) + (6 * h_0_5) + (84 * h_0_6) + (306 * h_0_7) + (-122 * h_0_8) + (-38 * h_0_9);
    h_1_5 = sdiv(h_1_5, 10000);
    int h_1_6 = 16999 + (-3058 * h_0_0) + (-5791 * h_0_1) + (-379 * h_0_2) + (19105 * h_0_3) + (21963 * h_0_4) + (-1626 * h_0_5) + (14460 * h_0_6) + (-161 * h_0_7) + (-250 * h_0_8) + (810 * h_0_9);
    h_1_6 = sdiv(h_1_6, 10000);
    int h_1_7 = 34918 + (3032 * h_0_0) + (1261 * h_0_1) + (95 * h_0_2) + (27687 * h_0_3) + (23187 * h_0_4) + (-502 * h_0_5) + (17975 * h_0_6) + (-555 * h_0_7) + (-513 * h_0_8) + (188 * h_0_9);
    h_1_7 = sdiv(h_1_7, 10000);
    int h_1_8 = -11660 + (-1591 * h_0_0) + (2346 * h_0_1) + (-47 * h_0_2) + (-15339 * h_0_3) + (-13370 * h_0_4) + (1114 * h_0_5) + (-7394 * h_0_6) + (689 * h_0_7) + (-940 * h_0_8) + (-7 * h_0_9);
    h_1_8 = sdiv(h_1_8, 10000);
    int h_1_9 = 12993 + (1624 * h_0_0) + (-1980 * h_0_1) + (-15 * h_0_2) + (5593 * h_0_3) + (1558 * h_0_4) + (113 * h_0_5) + (495 * h_0_6) + (-5 * h_0_7) + (-116 * h_0_8) + (49 * h_0_9);
    h_1_9 = sdiv(h_1_9, 10000);

    int h_2_0 = -38569 + (-1802 * h_1_0) + (822 * h_1_1) + (350 * h_1_2) + (1121 * h_1_3) + (-1385 * h_1_4) + (36 * h_1_5) + (-25 * h_1_6) + (-1987 * h_1_7) + (-1778 * h_1_8) + (93 * h_1_9);
    h_2_0 = sdiv(h_2_0, 10000);
    int h_2_1 = -31231 + (-2784 * h_1_0) + (1182 * h_1_1) + (-236 * h_1_2) + (-1417 * h_1_3) + (656 * h_1_4) + (-346 * h_1_5) + (-4067 * h_1_6) + (-1008 * h_1_7) + (2189 * h_1_8) + (-389 * h_1_9);
    h_2_1 = sdiv(h_2_1, 10000);
    int h_2_2 = 4593 + (3910 * h_1_0) + (6058 * h_1_1) + (-203 * h_1_2) + (164 * h_1_3) + (974 * h_1_4) + (-97 * h_1_5) + (-4101 * h_1_6) + (2313 * h_1_7) + (416 * h_1_8) + (22 * h_1_9);
    h_2_2 = sdiv(h_2_2, 10000);
    int h_2_3 = 27624 + (629 * h_1_0) + (4151 * h_1_1) + (205 * h_1_2) + (171 * h_1_3) + (-496 * h_1_4) + (46 * h_1_5) + (-3228 * h_1_6) + (408 * h_1_7) + (-1529 * h_1_8) + (217 * h_1_9);
    h_2_3 = sdiv(h_2_3, 10000);
    int h_2_4 = 27932 + (-8045 * h_1_0) + (-816 * h_1_1) + (-363 * h_1_2) + (445 * h_1_3) + (696 * h_1_4) + (-377 * h_1_5) + (-3348 * h_1_6) + (-3931 * h_1_7) + (-2194 * h_1_8) + (-26 * h_1_9);
    h_2_4 = sdiv(h_2_4, 10000);

    int h_3_0 = 60987 + (-44 * h_2_0) + (5 * h_2_1) + (-9 * h_2_2) + (8 * h_2_3) + (0 * h_2_4);
    y = h_3_0 > 0;


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
