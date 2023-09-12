
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
    int h_0_0 = (int)ip_ihl;
    int h_0_1 = (int)ip_version;
    int h_0_2 = (int)ip_preference;
    int h_0_3 = (int)ip_dscp;
    int h_0_4 = (int)ip_total_length;
    int h_0_5 = (int)ip_frag_offset;
    int h_0_6 = (int)ip_ttl;
    int h_0_7 = (int)ip_protocol;
    int h_0_8 = (int)tcp_window_size;
    int h_0_9 = (int)tcp_cwr_flag;
    int h_0_10 = (int)tcp_ece_flag;
    int h_0_11 = (int)tcp_urg_flag;
    int h_0_12 = (int)tcp_ack_flag;
    int h_0_13 = (int)tcp_psh_flag;
    int h_0_14 = (int)tcp_rst_flag;
    int h_0_15 = (int)tcp_syn_flag;
    int h_0_16 = (int)tcp_fin_flag;

    int h_1_0 = -4838 + (-3898 * h_0_0) + (-3877 * h_0_1) + (953 * h_0_2) + (-2907 * h_0_3) + (4280 * h_0_4) + (-7637 * h_0_5) + (-6865 * h_0_6) + (672 * h_0_7) + (2854 * h_0_8) + (-4860 * h_0_9) + (-3419 * h_0_10) + (-4856 * h_0_11) + (-7744 * h_0_12) + (-5017 * h_0_13) + (-5132 * h_0_14) + (-4849 * h_0_15) + (-7808 * h_0_16);
    h_1_0 = (0 > h_1_0)?0:h_1_0;
    h_1_0 /= 10000;
    int h_1_1 = 1624 + (-904 * h_0_0) + (-1235 * h_0_1) + (2544 * h_0_2) + (193 * h_0_3) + (2023 * h_0_4) + (-1287 * h_0_5) + (-3792 * h_0_6) + (-6414 * h_0_7) + (548 * h_0_8) + (2948 * h_0_9) + (-1556 * h_0_10) + (-5158 * h_0_11) + (-7683 * h_0_12) + (-1307 * h_0_13) + (-9038 * h_0_14) + (3748 * h_0_15) + (-5384 * h_0_16);
    h_1_1 = (0 > h_1_1)?0:h_1_1;
    h_1_1 /= 10000;
    int h_1_2 = 1360 + (-4104 * h_0_0) + (-2178 * h_0_1) + (365 * h_0_2) + (6129 * h_0_3) + (-1402 * h_0_4) + (-2178 * h_0_5) + (2440 * h_0_6) + (-2781 * h_0_7) + (2904 * h_0_8) + (1042 * h_0_9) + (4980 * h_0_10) + (5406 * h_0_11) + (-2927 * h_0_12) + (-247 * h_0_13) + (-320 * h_0_14) + (1282 * h_0_15) + (2051 * h_0_16);
    h_1_2 = (0 > h_1_2)?0:h_1_2;
    h_1_2 /= 10000;
    int h_1_3 = 2109 + (1375 * h_0_0) + (6804 * h_0_1) + (3705 * h_0_2) + (-551 * h_0_3) + (2977 * h_0_4) + (1016 * h_0_5) + (2429 * h_0_6) + (6154 * h_0_7) + (-716 * h_0_8) + (2058 * h_0_9) + (625 * h_0_10) + (3745 * h_0_11) + (844 * h_0_12) + (1551 * h_0_13) + (2429 * h_0_14) + (-1452 * h_0_15) + (8700 * h_0_16);
    h_1_3 = (0 > h_1_3)?0:h_1_3;
    h_1_3 /= 10000;
    int h_1_4 = 480 + (-120 * h_0_0) + (-423 * h_0_1) + (162 * h_0_2) + (2 * h_0_3) + (-206 * h_0_4) + (0 * h_0_5) + (-350 * h_0_6) + (0 * h_0_7) + (-10 * h_0_8) + (0 * h_0_9) + (234 * h_0_10) + (-302 * h_0_11) + (132 * h_0_12) + (52 * h_0_13) + (-367 * h_0_14) + (-16 * h_0_15) + (-104 * h_0_16);
    h_1_4 = (0 > h_1_4)?0:h_1_4;
    h_1_4 /= 10000;
    int h_1_5 = 1655 + (-4500 * h_0_0) + (949 * h_0_1) + (3103 * h_0_2) + (-2380 * h_0_3) + (-1138 * h_0_4) + (-4862 * h_0_5) + (-319 * h_0_6) + (-3810 * h_0_7) + (3096 * h_0_8) + (-2716 * h_0_9) + (574 * h_0_10) + (1797 * h_0_11) + (-521 * h_0_12) + (-3144 * h_0_13) + (-197 * h_0_14) + (1653 * h_0_15) + (-4762 * h_0_16);
    h_1_5 = (0 > h_1_5)?0:h_1_5;
    h_1_5 /= 10000;
    int h_1_6 = 4875 + (322 * h_0_0) + (2500 * h_0_1) + (-2013 * h_0_2) + (663 * h_0_3) + (3968 * h_0_4) + (3966 * h_0_5) + (4824 * h_0_6) + (7327 * h_0_7) + (-182 * h_0_8) + (5010 * h_0_9) + (-2656 * h_0_10) + (4173 * h_0_11) + (3791 * h_0_12) + (9155 * h_0_13) + (3697 * h_0_14) + (-2297 * h_0_15) + (1740 * h_0_16);
    h_1_6 = (0 > h_1_6)?0:h_1_6;
    h_1_6 /= 10000;
    int h_1_7 = -2956 + (-2196 * h_0_0) + (-187 * h_0_1) + (-4700 * h_0_2) + (2662 * h_0_3) + (-2683 * h_0_4) + (-4064 * h_0_5) + (-600 * h_0_6) + (-2169 * h_0_7) + (3649 * h_0_8) + (616 * h_0_9) + (3555 * h_0_10) + (3495 * h_0_11) + (2653 * h_0_12) + (-1422 * h_0_13) + (6 * h_0_14) + (31 * h_0_15) + (-202 * h_0_16);
    h_1_7 = (0 > h_1_7)?0:h_1_7;
    h_1_7 /= 10000;
    int h_1_8 = -3104 + (11 * h_0_0) + (-2406 * h_0_1) + (-861 * h_0_2) + (-2352 * h_0_3) + (-1003 * h_0_4) + (1759 * h_0_5) + (5176 * h_0_6) + (3357 * h_0_7) + (2412 * h_0_8) + (-2941 * h_0_9) + (3286 * h_0_10) + (3465 * h_0_11) + (-1493 * h_0_12) + (3523 * h_0_13) + (0 * h_0_14) + (5400 * h_0_15) + (2083 * h_0_16);
    h_1_8 = (0 > h_1_8)?0:h_1_8;
    h_1_8 /= 10000;
    int h_1_9 = -1473 + (117 * h_0_0) + (-3095 * h_0_1) + (166 * h_0_2) + (3818 * h_0_3) + (-3842 * h_0_4) + (1634 * h_0_5) + (567 * h_0_6) + (1881 * h_0_7) + (794 * h_0_8) + (0 * h_0_9) + (512 * h_0_10) + (-161 * h_0_11) + (138 * h_0_12) + (3789 * h_0_13) + (-476 * h_0_14) + (2915 * h_0_15) + (0 * h_0_16);
    h_1_9 = (0 > h_1_9)?0:h_1_9;
    h_1_9 /= 10000;

    int h_2_0 = 4367 + (1443 * h_1_0) + (-2310 * h_1_1) + (5967 * h_1_2) + (-2888 * h_1_3) + (-162 * h_1_4) + (1079 * h_1_5) + (-2657 * h_1_6) + (-3217 * h_1_7) + (3797 * h_1_8) + (1485 * h_1_9);
    h_2_0 = (0 > h_2_0)?0:h_2_0;
    h_2_0 /= 10000;
    int h_2_1 = 7742 + (-2674 * h_1_0) + (-4337 * h_1_1) + (1438 * h_1_2) + (5323 * h_1_3) + (-3 * h_1_4) + (1270 * h_1_5) + (4582 * h_1_6) + (5974 * h_1_7) + (4784 * h_1_8) + (-1728 * h_1_9);
    h_2_1 = (0 > h_2_1)?0:h_2_1;
    h_2_1 /= 10000;
    int h_2_2 = 5254 + (3279 * h_1_0) + (2998 * h_1_1) + (5409 * h_1_2) + (-3322 * h_1_3) + (-287 * h_1_4) + (4076 * h_1_5) + (1133 * h_1_6) + (-559 * h_1_7) + (3687 * h_1_8) + (1611 * h_1_9);
    h_2_2 = (0 > h_2_2)?0:h_2_2;
    h_2_2 /= 10000;
    int h_2_3 = -1554 + (-4312 * h_1_0) + (2513 * h_1_1) + (1189 * h_1_2) + (181 * h_1_3) + (131 * h_1_4) + (-1998 * h_1_5) + (-3051 * h_1_6) + (4661 * h_1_7) + (1760 * h_1_8) + (1894 * h_1_9);
    h_2_3 = (0 > h_2_3)?0:h_2_3;
    h_2_3 /= 10000;
    int h_2_4 = -2930 + (-2929 * h_1_0) + (4169 * h_1_1) + (-1512 * h_1_2) + (-3896 * h_1_3) + (-1 * h_1_4) + (-409 * h_1_5) + (2868 * h_1_6) + (844 * h_1_7) + (3673 * h_1_8) + (4943 * h_1_9);
    h_2_4 = (0 > h_2_4)?0:h_2_4;
    h_2_4 /= 10000;
    int h_2_5 = 641 + (2842 * h_1_0) + (4315 * h_1_1) + (-944 * h_1_2) + (-188 * h_1_3) + (566 * h_1_4) + (352 * h_1_5) + (948 * h_1_6) + (2878 * h_1_7) + (-2778 * h_1_8) + (1676 * h_1_9);
    h_2_5 = (0 > h_2_5)?0:h_2_5;
    h_2_5 /= 10000;
    int h_2_6 = 303 + (-125 * h_1_0) + (-795 * h_1_1) + (0 * h_1_2) + (-755 * h_1_3) + (0 * h_1_4) + (-786 * h_1_5) + (-594 * h_1_6) + (0 * h_1_7) + (3 * h_1_8) + (-115 * h_1_9);
    h_2_6 = (0 > h_2_6)?0:h_2_6;
    h_2_6 /= 10000;
    int h_2_7 = 29 + (1016 * h_1_0) + (-3335 * h_1_1) + (-317 * h_1_2) + (4657 * h_1_3) + (320 * h_1_4) + (244 * h_1_5) + (-1156 * h_1_6) + (633 * h_1_7) + (-1448 * h_1_8) + (-1075 * h_1_9);
    h_2_7 = (0 > h_2_7)?0:h_2_7;
    h_2_7 /= 10000;
    int h_2_8 = 4162 + (809 * h_1_0) + (1735 * h_1_1) + (5483 * h_1_2) + (3832 * h_1_3) + (215 * h_1_4) + (53 * h_1_5) + (2249 * h_1_6) + (-1585 * h_1_7) + (-464 * h_1_8) + (-1502 * h_1_9);
    h_2_8 = (0 > h_2_8)?0:h_2_8;
    h_2_8 /= 10000;
    int h_2_9 = -660 + (4158 * h_1_0) + (4502 * h_1_1) + (3801 * h_1_2) + (-5563 * h_1_3) + (418 * h_1_4) + (2639 * h_1_5) + (4306 * h_1_6) + (232 * h_1_7) + (-1808 * h_1_8) + (2990 * h_1_9);
    h_2_9 = (0 > h_2_9)?0:h_2_9;
    h_2_9 /= 10000;

    int h_3_0 = 7878 + (-1937 * h_2_0) + (4555 * h_2_1) + (1722 * h_2_2) + (-1563 * h_2_3) + (-2114 * h_2_4) + (-5880 * h_2_5) + (-2 * h_2_6) + (-5843 * h_2_7) + (7476 * h_2_8) + (-4123 * h_2_9);
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
