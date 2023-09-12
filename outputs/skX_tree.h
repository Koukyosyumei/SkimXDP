#include <stdint.h>

inline int filter_func(unsigned int ip_ihl, unsigned int ip_version,
                        int ip_preference, int ip_dscp, uint16_t ip_total_length,
                        uint16_t ip_frag_offset, uint8_t ip_ttl, uint8_t ip_protocol,
                        uint16_t tcp_source_port, uint16_t tcp_dest_port,
                        unsigned int tcp_sequence_num, unsigned int tcp_ack_num,
                        uint16_t tcp_window_size, uint16_t tcp_urgent_pointer, uint16_t tcp_cwr_flag,
                        uint16_t tcp_ece_flag, uint16_t tcp_urg_flag, uint16_t tcp_ack_flag,
                        uint16_t tcp_psh_flag, uint16_t tcp_rst_flag, uint16_t tcp_syn_flag, uint16_t tcp_fin_flag) {
  if (ip_dscp <= 1) {
   if (tcp_psh_flag <= 0) {
    if (tcp_window_size <= 114) {
     return 1;
    }
    else {
     if (tcp_window_size <= 46600) {
      if (tcp_fin_flag <= 0) {
       if (tcp_window_size <= 500) {
        if (tcp_window_size <= 246) {
         if (tcp_window_size <= 231) {
          return 1;
         }
         else {
          return 1;
         }
        }
        else {
         if (tcp_window_size <= 372) {
          return 0;
         }
         else {
          if (tcp_window_size <= 499) {
           if (tcp_window_size <= 498) {
            if (tcp_window_size <= 494) {
             return 1;
            }
            else {
             if (tcp_window_size <= 497) {
              return 1;
             }
             else {
              return 1;
             }
            }
           }
           else {
            return 1;
           }
          }
          else {
           return 0;
          }
         }
        }
       }
       else {
        if (tcp_window_size <= 501) {
         return 1;
        }
        else {
         if (tcp_rst_flag <= 0) {
          if (ip_total_length <= 14336) {
           return 1;
          }
          else {
           return 1;
          }
         }
         else {
          return 1;
         }
        }
       }
      }
      else {
       return 1;
      }
     }
     else {
      return 1;
     }
    }
   }
   else {
    if (tcp_window_size <= 246) {
     if (ip_total_length <= 24064) {
      if (ip_total_length <= 23552) {
       return 1;
      }
      else {
       return 1;
      }
     }
     else {
      return 1;
     }
    }
    else {
     if (tcp_window_size <= 395) {
      return 0;
     }
     else {
      if (ip_total_length <= 45953) {
       if (ip_total_length <= 41216) {
        if (ip_total_length <= 17408) {
         if (tcp_window_size <= 501) {
          if (ip_total_length <= 15744) {
           return 1;
          }
          else {
           return 0;
          }
         }
         else {
          return 0;
         }
        }
        else {
         if (tcp_window_size <= 501) {
          if (ip_total_length <= 24448) {
           return 1;
          }
          else {
           if (ip_total_length <= 31488) {
            return 0;
           }
           else {
            return 1;
           }
          }
         }
         else {
          if (ip_total_length <= 24064) {
           if (ip_total_length <= 22016) {
            return 1;
           }
           else {
            return 0;
           }
          }
          else {
           return 1;
          }
         }
        }
       }
       else {
        return 0;
       }
      }
      else {
       return 1;
      }
     }
    }
   }
  }
  else {
   if (tcp_window_size <= 10901) {
    return 0;
   }
   else {
    return 1;
   }
  }
}