#include <stdint.h>

inline int filter_func(unsigned int ip_ihl, unsigned int ip_version,
                        int ip_preference, int ip_dscp, uint16_t ip_total_length,
                        uint16_t ip_frag_offset, uint8_t ip_ttl, uint8_t ip_protocol,
                        uint16_t tcp_source_port, uint16_t tcp_dest_port,
                        unsigned int tcp_sequence_num, unsigned int tcp_ack_num,
                        uint16_t tcp_window_size, uint16_t tcp_urgent_pointer, uint16_t tcp_cwr_flag,
                        uint16_t tcp_ece_flag, uint16_t tcp_urg_flag, uint16_t tcp_ack_flag,
                        uint16_t tcp_psh_flag, uint16_t tcp_rst_flag, uint16_t tcp_syn_flag, uint16_t tcp_fin_flag) {
  return (23 + (115 * ip_ihl) + (92 * ip_version) + (238 * ip_preference) + (-27083 * ip_dscp) + (0 * ip_total_length) + (-1069 * ip_frag_offset) + (1477 * ip_ttl) + (658 * ip_protocol) + (0 * tcp_window_size) + (10 * tcp_cwr_flag) + (39 * tcp_ece_flag) + (39 * tcp_urg_flag) + (-1395 * tcp_ack_flag) + (996 * tcp_psh_flag) + (7926 * tcp_rst_flag) + (1536 * tcp_syn_flag) + (588 * tcp_fin_flag)) > 0;
}