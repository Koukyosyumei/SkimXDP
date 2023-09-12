#include <stdint.h>

inline int filter_func(unsigned int ip_ihl, unsigned int ip_version,
                        int ip_preference, int ip_dscp, uint16_t ip_total_length,
                        uint16_t ip_frag_offset, uint8_t ip_ttl, uint8_t ip_protocol,
                        uint16_t tcp_source_port, uint16_t tcp_dest_port,
                        unsigned int tcp_sequence_num, unsigned int tcp_ack_num,
                        uint16_t tcp_window_size, uint16_t tcp_urgent_pointer, uint16_t tcp_cwr_flag,
                        uint16_t tcp_ece_flag, uint16_t tcp_urg_flag, uint16_t tcp_ack_flag,
                        uint16_t tcp_psh_flag, uint16_t tcp_rst_flag, uint16_t tcp_syn_flag, uint16_t tcp_fin_flag) {
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

 int h_1_0 = 2156 + (0 * h_0_0) + (-1753 * h_0_1) + (-713 * h_0_2) + (-497 * h_0_3) + (-3 * h_0_4) + (0 * h_0_5) + (-410 * h_0_6) + (-1537 * h_0_7) + (0 * h_0_8) + (-751 * h_0_9) + (434 * h_0_10) + (-69 * h_0_11) + (854 * h_0_12) + (-1111 * h_0_13) + (-583 * h_0_14) + (-1020 * h_0_15) + (1424 * h_0_16);
 h_1_0 = (0 > h_1_0)?0:h_1_0;
 h_1_0 /= 10000;
 int h_1_1 = -2645 + (1904 * h_0_0) + (-2793 * h_0_1) + (-3786 * h_0_2) + (-2311 * h_0_3) + (-114 * h_0_4) + (1509 * h_0_5) + (3677 * h_0_6) + (1344 * h_0_7) + (24 * h_0_8) + (-439 * h_0_9) + (3327 * h_0_10) + (1261 * h_0_11) + (3862 * h_0_12) + (-5809 * h_0_13) + (3938 * h_0_14) + (-1018 * h_0_15) + (312 * h_0_16);
 h_1_1 = (0 > h_1_1)?0:h_1_1;
 h_1_1 /= 10000;

 int h_2_0 = -14921 + (1512 * h_1_0) + (9066 * h_1_1);
 return h_2_0 > 0;
}