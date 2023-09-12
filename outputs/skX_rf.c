
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
    if (tcp_window_size <= 1045248) {
     if (ip_total_length <= 19) {
      y += 0;
     }
     else {
      if (ip_ttl <= 96) {
       if (tcp_syn_flag <= 0) {
        if (ip_total_length <= 72) {
         if (ip_ttl <= 32) {
          y += 0;
         }
         else {
          if (ip_total_length <= 58) {
           y += 0;
          }
          else {
           if (ip_total_length <= 71) {
            if (ip_total_length <= 70) {
             if (ip_total_length <= 60) {
              if (ip_total_length <= 59) {
               y += 0;
              }
              else {
               y += 0;
              }
             }
             else {
              if (ip_total_length <= 62) {
               y += 1;
              }
              else {
               if (ip_total_length <= 66) {
                y += 0;
               }
               else {
                y += 0;
               }
              }
             }
            }
            else {
             y += 1;
            }
           }
           else {
            y += 0;
           }
          }
         }
        }
        else {
         if (ip_ttl <= 8) {
          y += 0;
         }
         else {
          y += 1;
         }
        }
       }
       else {
        if (tcp_syn_flag <= 0) {
         if (ip_total_length <= 46) {
          if (tcp_window_size <= 2944) {
           y += 1;
          }
          else {
           y += 0;
          }
         }
         else {
          if (tcp_window_size <= 7456) {
           if (ip_total_length <= 241) {
            if (tcp_fin_flag <= 0) {
             if (ip_total_length <= 139) {
              y += 1;
             }
             else {
              if (ip_total_length <= 140) {
               y += 1;
              }
              else {
               y += 1;
              }
             }
            }
            else {
             y += 1;
            }
           }
           else {
            if (tcp_window_size <= 6944) {
             if (tcp_window_size <= 6368) {
              y += 1;
             }
             else {
              if (ip_total_length <= 619) {
               if (ip_total_length <= 615) {
                if (ip_total_length <= 257) {
                 y += 0;
                }
                else {
                 if (ip_total_length <= 306) {
                  if (ip_total_length <= 276) {
                   y += 1;
                  }
                  else {
                   y += 0;
                  }
                 }
                 else {
                  if (ip_total_length <= 516) {
                   y += 1;
                  }
                  else {
                   if (ip_total_length <= 597) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
               }
               else {
                y += 0;
               }
              }
              else {
               if (ip_total_length <= 669) {
                y += 1;
               }
               else {
                if (ip_total_length <= 676) {
                 if (ip_total_length <= 675) {
                  if (ip_total_length <= 670) {
                   y += 1;
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  y += 0;
                 }
                }
                else {
                 if (ip_total_length <= 1173) {
                  if (ip_total_length <= 874) {
                   if (ip_total_length <= 712) {
                    if (ip_total_length <= 690) {
                     if (ip_total_length <= 689) {
                      y += 1;
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    if (ip_total_length <= 714) {
                     if (ip_total_length <= 713) {
                      y += 0;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                  else {
                   if (ip_total_length <= 929) {
                    if (ip_total_length <= 884) {
                     if (ip_total_length <= 879) {
                      y += 0;
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     y += 0;
                    }
                   }
                   else {
                    if (ip_total_length <= 994) {
                     y += 1;
                    }
                    else {
                     if (ip_total_length <= 996) {
                      y += 0;
                     }
                     else {
                      if (ip_total_length <= 1171) {
                       if (ip_total_length <= 1132) {
                        if (ip_total_length <= 1076) {
                         y += 1;
                        }
                        else {
                         y += 0;
                        }
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       y += 0;
                      }
                     }
                    }
                   }
                  }
                 }
                 else {
                  if (ip_total_length <= 1361) {
                   y += 1;
                  }
                  else {
                   if (ip_total_length <= 1366) {
                    y += 0;
                   }
                   else {
                    if (ip_total_length <= 1476) {
                     if (ip_total_length <= 1433) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     if (ip_total_length <= 1495) {
                      y += 1;
                     }
                     else {
                      y += 1;
                     }
                    }
                   }
                  }
                 }
                }
               }
              }
             }
            }
            else {
             if (ip_total_length <= 1495) {
              y += 1;
             }
             else {
              if (tcp_window_size <= 7328) {
               if (tcp_window_size <= 7264) {
                if (tcp_window_size <= 7008) {
                 y += 0;
                }
                else {
                 y += 1;
                }
               }
               else {
                y += 0;
               }
              }
              else {
               if (tcp_window_size <= 7392) {
                y += 1;
               }
               else {
                y += 1;
               }
              }
             }
            }
           }
          }
          else {
           if (tcp_window_size <= 21152) {
            if (tcp_window_size <= 21088) {
             if (ip_total_length <= 1495) {
              if (tcp_fin_flag <= 0) {
               if (tcp_window_size <= 8480) {
                if (ip_total_length <= 1066) {
                 if (tcp_window_size <= 8288) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 411) {
                   y += 1;
                  }
                  else {
                   if (ip_total_length <= 470) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 8096) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 8160) {
                   if (ip_total_length <= 1139) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   if (tcp_window_size <= 8416) {
                    y += 1;
                   }
                   else {
                    if (ip_total_length <= 1217) {
                     if (ip_total_length <= 1210) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                 }
                }
               }
               else {
                if (ip_total_length <= 858) {
                 y += 1;
                }
                else {
                 if (tcp_window_size <= 11232) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 11360) {
                   y += 0;
                  }
                  else {
                   if (tcp_window_size <= 17472) {
                    if (ip_total_length <= 863) {
                     if (tcp_window_size <= 16032) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     if (ip_total_length <= 1138) {
                      if (ip_total_length <= 1111) {
                       y += 1;
                      }
                      else {
                       y += 0;
                      }
                     }
                     else {
                      if (tcp_window_size <= 12704) {
                       if (tcp_window_size <= 12416) {
                        y += 1;
                       }
                       else {
                        y += 0;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
               }
              }
              else {
               y += 1;
              }
             }
             else {
              if (tcp_window_size <= 10272) {
               if (tcp_window_size <= 10144) {
                if (tcp_window_size <= 7776) {
                 if (tcp_window_size <= 7712) {
                  y += 1;
                 }
                 else {
                  y += 0;
                 }
                }
                else {
                 if (tcp_window_size <= 9056) {
                  if (tcp_window_size <= 7968) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 8032) {
                    y += 1;
                   }
                   else {
                    if (tcp_window_size <= 8736) {
                     if (tcp_window_size <= 8608) {
                      if (tcp_window_size <= 8544) {
                       y += 1;
                      }
                      else {
                       y += 0;
                      }
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     if (tcp_window_size <= 8960) {
                      if (tcp_window_size <= 8832) {
                       y += 0;
                      }
                      else {
                       y += 0;
                      }
                     }
                     else {
                      y += 1;
                     }
                    }
                   }
                  }
                 }
                 else {
                  if (tcp_window_size <= 9120) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 9184) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
               }
               else {
                if (tcp_window_size <= 10208) {
                 y += 0;
                }
                else {
                 y += 1;
                }
               }
              }
              else {
               if (tcp_window_size <= 15392) {
                if (tcp_window_size <= 15328) {
                 if (tcp_window_size <= 12960) {
                  if (tcp_window_size <= 11232) {
                   if (tcp_window_size <= 11168) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  if (tcp_window_size <= 13152) {
                   if (tcp_window_size <= 13088) {
                    if (tcp_window_size <= 13024) {
                     y += 0;
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   if (tcp_window_size <= 13600) {
                    y += 1;
                   }
                   else {
                    if (tcp_window_size <= 13664) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 14432) {
                      if (tcp_window_size <= 13920) {
                       if (tcp_window_size <= 13824) {
                        y += 1;
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                     else {
                      if (tcp_window_size <= 14496) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                  }
                 }
                }
                else {
                 y += 1;
                }
               }
               else {
                if (tcp_window_size <= 19296) {
                 if (tcp_window_size <= 15840) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 15936) {
                   y += 0;
                  }
                  else {
                   if (tcp_window_size <= 17376) {
                    y += 1;
                   }
                   else {
                    if (tcp_window_size <= 17472) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 18656) {
                      y += 1;
                     }
                     else {
                      if (tcp_window_size <= 18720) {
                       y += 1;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 19360) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 20384) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 20448) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
               }
              }
             }
            }
            else {
             if (ip_total_length <= 1140) {
              y += 1;
             }
             else {
              y += 0;
             }
            }
           }
           else {
            if (ip_total_length <= 1499) {
             if (tcp_window_size <= 45088) {
              if (tcp_window_size <= 45024) {
               if (ip_total_length <= 470) {
                if (ip_total_length <= 468) {
                 y += 1;
                }
                else {
                 y += 0;
                }
               }
               else {
                if (tcp_window_size <= 30720) {
                 if (tcp_window_size <= 30624) {
                  if (tcp_window_size <= 27424) {
                   y += 1;
                  }
                  else {
                   if (ip_total_length <= 664) {
                    if (ip_total_length <= 663) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 27904) {
                      y += 0;
                     }
                     else {
                      y += 1;
                     }
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                 else {
                  if (ip_total_length <= 1176) {
                   y += 1;
                  }
                  else {
                   y += 0;
                  }
                 }
                }
                else {
                 y += 1;
                }
               }
              }
              else {
               if (ip_total_length <= 556) {
                if (ip_total_length <= 347) {
                 y += 1;
                }
                else {
                 y += 0;
                }
               }
               else {
                y += 1;
               }
              }
             }
             else {
              y += 1;
             }
            }
            else {
             if (tcp_window_size <= 25888) {
              if (tcp_window_size <= 25824) {
               if (tcp_window_size <= 24288) {
                if (tcp_window_size <= 23584) {
                 y += 1;
                }
                else {
                 if (tcp_window_size <= 23680) {
                  y += 0;
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                if (tcp_window_size <= 24352) {
                 y += 0;
                }
                else {
                 y += 1;
                }
               }
              }
              else {
               y += 1;
              }
             }
             else {
              if (tcp_window_size <= 48448) {
               if (tcp_window_size <= 48352) {
                if (tcp_window_size <= 27104) {
                 if (tcp_window_size <= 26976) {
                  y += 1;
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 if (tcp_window_size <= 43488) {
                  if (tcp_window_size <= 36576) {
                   if (tcp_window_size <= 36512) {
                    if (tcp_window_size <= 30432) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 30496) {
                      y += 1;
                     }
                     else {
                      if (tcp_window_size <= 33984) {
                       y += 1;
                      }
                      else {
                       if (tcp_window_size <= 34080) {
                        y += 1;
                       }
                       else {
                        y += 1;
                       }
                      }
                     }
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  if (tcp_window_size <= 43584) {
                   y += 1;
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
               else {
                y += 1;
               }
              }
              else {
               y += 1;
              }
             }
            }
           }
          }
         }
        }
        else {
         if (ip_ttl <= 61) {
          y += 1;
         }
         else {
          if (tcp_window_size <= 35040) {
           if (ip_total_length <= 56) {
            if (ip_total_length <= 48) {
             y += 1;
            }
            else {
             y += 0;
            }
           }
           else {
            y += 1;
           }
          }
          else {
           y += 1;
          }
         }
        }
       }
      }
      else {
       y += 0;
      }
     }
    }
    else {
     if (ip_ttl <= 96) {
      y += 1;
     }
     else {
      y += 0;
     }
    }
    if (tcp_window_size <= 1041152) {
     if (ip_total_length <= 19) {
      y += 0;
     }
     else {
      if (tcp_fin_flag <= 0) {
       if (tcp_fin_flag <= 0) {
        if (ip_total_length <= 72) {
         if (ip_protocol <= 9) {
          y += 0;
         }
         else {
          if (ip_total_length <= 71) {
           if (ip_total_length <= 70) {
            if (ip_total_length <= 62) {
             if (ip_total_length <= 58) {
              y += 0;
             }
             else {
              if (ip_total_length <= 60) {
               y += 1;
              }
              else {
               y += 1;
              }
             }
            }
            else {
             y += 0;
            }
           }
           else {
            y += 1;
           }
          }
          else {
           y += 0;
          }
         }
        }
        else {
         if (ip_ttl <= 40) {
          if (ip_total_length <= 265) {
           y += 0;
          }
          else {
           y += 0;
          }
         }
         else {
          if (ip_total_length <= 177) {
           y += 1;
          }
          else {
           if (ip_total_length <= 294) {
            y += 0;
           }
           else {
            y += 1;
           }
          }
         }
        }
       }
       else {
        if (ip_ttl <= 96) {
         if (tcp_window_size <= 7392) {
          if (ip_total_length <= 48) {
           if (ip_total_length <= 42) {
            if (tcp_window_size <= 2944) {
             y += 1;
            }
            else {
             y += 0;
            }
           }
           else {
            y += 1;
           }
          }
          else {
           if (ip_total_length <= 55) {
            if (tcp_window_size <= 6376) {
             if (tcp_syn_flag <= 0) {
              y += 1;
             }
             else {
              y += 0;
             }
            }
            else {
             y += 1;
            }
           }
           else {
            if (ip_total_length <= 134) {
             y += 1;
            }
            else {
             if (tcp_window_size <= 6944) {
              if (ip_total_length <= 619) {
               if (ip_total_length <= 615) {
                if (ip_total_length <= 140) {
                 y += 0;
                }
                else {
                 if (ip_total_length <= 241) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 257) {
                   y += 0;
                  }
                  else {
                   if (ip_total_length <= 306) {
                    if (ip_total_length <= 276) {
                     y += 1;
                    }
                    else {
                     y += 0;
                    }
                   }
                   else {
                    if (ip_total_length <= 516) {
                     y += 1;
                    }
                    else {
                     if (ip_total_length <= 597) {
                      y += 0;
                     }
                     else {
                      y += 1;
                     }
                    }
                   }
                  }
                 }
                }
               }
               else {
                y += 0;
               }
              }
              else {
               if (ip_total_length <= 675) {
                y += 1;
               }
               else {
                if (ip_total_length <= 1173) {
                 if (tcp_window_size <= 6368) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 867) {
                   if (ip_total_length <= 676) {
                    y += 0;
                   }
                   else {
                    if (ip_total_length <= 687) {
                     if (ip_total_length <= 686) {
                      y += 1;
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     if (ip_total_length <= 711) {
                      y += 1;
                     }
                     else {
                      if (ip_total_length <= 714) {
                       if (ip_total_length <= 713) {
                        y += 1;
                       }
                       else {
                        y += 0;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                  }
                  else {
                   if (ip_total_length <= 929) {
                    y += 0;
                   }
                   else {
                    if (ip_total_length <= 1044) {
                     if (ip_total_length <= 981) {
                      y += 1;
                     }
                     else {
                      if (ip_total_length <= 996) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                    else {
                     if (ip_total_length <= 1162) {
                      y += 0;
                     }
                     else {
                      if (ip_total_length <= 1171) {
                       y += 1;
                      }
                      else {
                       y += 0;
                      }
                     }
                    }
                   }
                  }
                 }
                }
                else {
                 if (ip_total_length <= 1305) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 1306) {
                   y += 0;
                  }
                  else {
                   if (tcp_window_size <= 6368) {
                    y += 1;
                   }
                   else {
                    if (ip_total_length <= 1495) {
                     y += 1;
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                 }
                }
               }
              }
             }
             else {
              if (tcp_window_size <= 7168) {
               if (tcp_window_size <= 7040) {
                if (ip_total_length <= 1495) {
                 if (ip_total_length <= 1353) {
                  y += 0;
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 y += 0;
                }
               }
               else {
                y += 0;
               }
              }
              else {
               if (tcp_window_size <= 7264) {
                if (ip_total_length <= 1144) {
                 y += 1;
                }
                else {
                 y += 0;
                }
               }
               else {
                if (ip_total_length <= 1194) {
                 y += 1;
                }
                else {
                 if (tcp_window_size <= 7328) {
                  y += 0;
                 }
                 else {
                  y += 1;
                 }
                }
               }
              }
             }
            }
           }
          }
         }
         else {
          if (ip_total_length <= 46) {
           y += 0;
          }
          else {
           if (ip_total_length <= 1499) {
            if (tcp_window_size <= 45088) {
             if (tcp_window_size <= 45024) {
              if (ip_total_length <= 857) {
               if (tcp_window_size <= 24992) {
                y += 1;
               }
               else {
                if (ip_total_length <= 470) {
                 if (ip_total_length <= 469) {
                  y += 1;
                 }
                 else {
                  y += 0;
                 }
                }
                else {
                 if (tcp_window_size <= 27488) {
                  if (tcp_window_size <= 27360) {
                   y += 1;
                  }
                  else {
                   if (ip_total_length <= 635) {
                    y += 1;
                   }
                   else {
                    y += 0;
                   }
                  }
                 }
                 else {
                  y += 1;
                 }
                }
               }
              }
              else {
               if (tcp_window_size <= 17504) {
                if (tcp_window_size <= 17056) {
                 if (tcp_window_size <= 12480) {
                  if (ip_total_length <= 1217) {
                   if (tcp_window_size <= 8480) {
                    if (tcp_window_size <= 8416) {
                     y += 1;
                    }
                    else {
                     if (ip_total_length <= 1210) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  if (ip_total_length <= 1133) {
                   if (ip_total_length <= 1111) {
                    if (tcp_window_size <= 14304) {
                     if (ip_total_length <= 1006) {
                      y += 1;
                     }
                     else {
                      if (ip_total_length <= 1039) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   if (tcp_window_size <= 12704) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
                else {
                 if (ip_total_length <= 906) {
                  y += 0;
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                if (tcp_window_size <= 30624) {
                 y += 1;
                }
                else {
                 if (ip_total_length <= 936) {
                  if (ip_total_length <= 922) {
                   y += 1;
                  }
                  else {
                   y += 0;
                  }
                 }
                 else {
                  if (ip_total_length <= 1182) {
                   if (ip_total_length <= 1178) {
                    y += 1;
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
              }
             }
             else {
              if (ip_total_length <= 556) {
               y += 0;
              }
              else {
               y += 1;
              }
             }
            }
            else {
             y += 1;
            }
           }
           else {
            if (tcp_window_size <= 21184) {
             if (tcp_window_size <= 21088) {
              if (tcp_window_size <= 10272) {
               if (tcp_window_size <= 10144) {
                if (tcp_window_size <= 9056) {
                 if (tcp_window_size <= 8032) {
                  if (tcp_window_size <= 7968) {
                   if (tcp_window_size <= 7776) {
                    if (tcp_window_size <= 7712) {
                     y += 1;
                    }
                    else {
                     y += 0;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  if (tcp_window_size <= 8832) {
                   if (tcp_window_size <= 8640) {
                    if (tcp_window_size <= 8544) {
                     y += 1;
                    }
                    else {
                     y += 0;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   if (tcp_window_size <= 8960) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 9184) {
                  if (tcp_window_size <= 9120) {
                   y += 0;
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  if (tcp_window_size <= 10080) {
                   if (tcp_window_size <= 9920) {
                    y += 1;
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
               else {
                if (tcp_window_size <= 10208) {
                 y += 0;
                }
                else {
                 y += 0;
                }
               }
              }
              else {
               if (tcp_window_size <= 13152) {
                if (tcp_window_size <= 13088) {
                 if (tcp_window_size <= 11680) {
                  if (tcp_window_size <= 11616) {
                   if (tcp_window_size <= 11232) {
                    if (tcp_window_size <= 11168) {
                     y += 1;
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 y += 0;
                }
               }
               else {
                if (tcp_window_size <= 13600) {
                 y += 1;
                }
                else {
                 if (tcp_window_size <= 13664) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 13984) {
                   if (tcp_window_size <= 13824) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   if (tcp_window_size <= 18656) {
                    if (tcp_window_size <= 17472) {
                     if (tcp_window_size <= 17376) {
                      if (tcp_window_size <= 15936) {
                       if (tcp_window_size <= 15840) {
                        if (tcp_window_size <= 15392) {
                         if (tcp_window_size <= 15328) {
                          if (tcp_window_size <= 14432) {
                           y += 1;
                          }
                          else {
                           if (tcp_window_size <= 14496) {
                            y += 0;
                           }
                           else {
                            y += 1;
                           }
                          }
                         }
                         else {
                          y += 1;
                         }
                        }
                        else {
                         y += 1;
                        }
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    if (tcp_window_size <= 19360) {
                     if (tcp_window_size <= 19296) {
                      if (tcp_window_size <= 18848) {
                       if (tcp_window_size <= 18720) {
                        y += 1;
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       if (tcp_window_size <= 18912) {
                        y += 1;
                       }
                       else {
                        y += 1;
                       }
                      }
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     if (tcp_window_size <= 20384) {
                      y += 1;
                     }
                     else {
                      if (tcp_window_size <= 20448) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                  }
                 }
                }
               }
              }
             }
             else {
              y += 0;
             }
            }
            else {
             if (tcp_window_size <= 24352) {
              if (tcp_window_size <= 24288) {
               if (tcp_window_size <= 23584) {
                y += 1;
               }
               else {
                if (tcp_window_size <= 23648) {
                 y += 0;
                }
                else {
                 y += 1;
                }
               }
              }
              else {
               y += 0;
              }
             }
             else {
              if (tcp_window_size <= 48448) {
               if (tcp_window_size <= 48352) {
                if (tcp_window_size <= 27104) {
                 if (tcp_window_size <= 26976) {
                  if (tcp_window_size <= 25888) {
                   if (tcp_window_size <= 25824) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 if (tcp_window_size <= 43552) {
                  if (tcp_window_size <= 43488) {
                   if (tcp_window_size <= 37856) {
                    if (tcp_window_size <= 37792) {
                     if (tcp_window_size <= 36512) {
                      if (tcp_window_size <= 30496) {
                       if (tcp_window_size <= 30432) {
                        y += 1;
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                     else {
                      if (tcp_window_size <= 36576) {
                       y += 1;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                y += 1;
               }
              }
              else {
               y += 1;
              }
             }
            }
           }
          }
         }
        }
        else {
         y += 0;
        }
       }
      }
      else {
       if (tcp_window_size <= 126592) {
        if (ip_total_length <= 46) {
         y += 0;
        }
        else {
         y += 1;
        }
       }
       else {
        if (ip_total_length <= 46) {
         y += 0;
        }
        else {
         y += 1;
        }
       }
      }
     }
    }
    else {
     if (ip_ttl <= 96) {
      y += 1;
     }
     else {
      y += 0;
     }
    }
    if (ip_ttl <= 96) {
     if (ip_total_length <= 19) {
      y += 0;
     }
     else {
      if (ip_ttl <= 8) {
       y += 0;
      }
      else {
       if (tcp_window_size <= 7488) {
        if (tcp_window_size <= 5832) {
         if (tcp_window_size <= 0) {
          if (ip_protocol <= 9) {
           y += 1;
          }
          else {
           if (ip_ttl <= 40) {
            y += 1;
           }
           else {
            if (ip_total_length <= 72) {
             if (ip_total_length <= 71) {
              if (ip_total_length <= 70) {
               if (ip_total_length <= 65) {
                if (ip_total_length <= 58) {
                 y += 0;
                }
                else {
                 if (ip_total_length <= 60) {
                  if (ip_total_length <= 59) {
                   y += 1;
                  }
                  else {
                   y += 0;
                  }
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                y += 0;
               }
              }
              else {
               y += 1;
              }
             }
             else {
              y += 0;
             }
            }
            else {
             y += 1;
            }
           }
          }
         }
         else {
          y += 1;
         }
        }
        else {
         if (tcp_window_size <= 5864) {
          if (ip_total_length <= 48) {
           y += 1;
          }
          else {
           y += 0;
          }
         }
         else {
          if (tcp_window_size <= 6944) {
           if (tcp_fin_flag <= 0) {
            if (tcp_window_size <= 6400) {
             y += 1;
            }
            else {
             if (ip_total_length <= 46) {
              y += 0;
             }
             else {
              if (ip_total_length <= 232) {
               y += 1;
              }
              else {
               if (ip_total_length <= 619) {
                if (ip_total_length <= 615) {
                 if (ip_total_length <= 257) {
                  y += 0;
                 }
                 else {
                  if (ip_total_length <= 597) {
                   if (ip_total_length <= 516) {
                    if (ip_total_length <= 306) {
                     if (ip_total_length <= 276) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    if (ip_total_length <= 529) {
                     y += 0;
                    }
                    else {
                     if (ip_total_length <= 558) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
                else {
                 y += 0;
                }
               }
               else {
                if (ip_total_length <= 1162) {
                 if (ip_total_length <= 1070) {
                  if (ip_total_length <= 867) {
                   if (ip_total_length <= 675) {
                    y += 1;
                   }
                   else {
                    if (ip_total_length <= 676) {
                     y += 0;
                    }
                    else {
                     if (ip_total_length <= 687) {
                      if (ip_total_length <= 686) {
                       y += 1;
                      }
                      else {
                       y += 1;
                      }
                     }
                     else {
                      if (ip_total_length <= 712) {
                       if (ip_total_length <= 690) {
                        if (ip_total_length <= 689) {
                         y += 1;
                        }
                        else {
                         y += 1;
                        }
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       if (ip_total_length <= 714) {
                        if (ip_total_length <= 713) {
                         y += 0;
                        }
                        else {
                         y += 0;
                        }
                       }
                       else {
                        y += 1;
                       }
                      }
                     }
                    }
                   }
                  }
                  else {
                   if (ip_total_length <= 929) {
                    if (ip_total_length <= 885) {
                     if (ip_total_length <= 879) {
                      y += 0;
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     y += 0;
                    }
                   }
                   else {
                    if (ip_total_length <= 981) {
                     y += 1;
                    }
                    else {
                     if (ip_total_length <= 996) {
                      y += 0;
                     }
                     else {
                      y += 1;
                     }
                    }
                   }
                  }
                 }
                 else {
                  y += 0;
                 }
                }
                else {
                 if (ip_total_length <= 1360) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 1366) {
                   y += 0;
                  }
                  else {
                   if (ip_total_length <= 1495) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
               }
              }
             }
            }
           }
           else {
            if (tcp_window_size <= 6400) {
             y += 0;
            }
            else {
             if (ip_total_length <= 46) {
              y += 0;
             }
             else {
              y += 1;
             }
            }
           }
          }
          else {
           if (ip_total_length <= 1495) {
            if (ip_total_length <= 46) {
             y += 0;
            }
            else {
             if (tcp_window_size <= 7168) {
              if (tcp_window_size <= 7072) {
               y += 1;
              }
              else {
               y += 0;
              }
             }
             else {
              y += 1;
             }
            }
           }
           else {
            if (tcp_window_size <= 7328) {
             if (tcp_window_size <= 7264) {
              if (tcp_window_size <= 7168) {
               if (tcp_window_size <= 7072) {
                if (tcp_window_size <= 7008) {
                 y += 0;
                }
                else {
                 y += 1;
                }
               }
               else {
                y += 0;
               }
              }
              else {
               y += 1;
              }
             }
             else {
              y += 0;
             }
            }
            else {
             if (tcp_window_size <= 7392) {
              y += 1;
             }
             else {
              y += 1;
             }
            }
           }
          }
         }
        }
       }
       else {
        if (tcp_window_size <= 21344) {
         if (ip_total_length <= 46) {
          y += 0;
         }
         else {
          if (tcp_fin_flag <= 0) {
           if (tcp_window_size <= 21088) {
            if (ip_total_length <= 1495) {
             if (ip_total_length <= 858) {
              y += 1;
             }
             else {
              if (ip_total_length <= 864) {
               if (tcp_window_size <= 16032) {
                y += 1;
               }
               else {
                y += 0;
               }
              }
              else {
               if (ip_total_length <= 1217) {
                if (ip_total_length <= 1210) {
                 if (tcp_window_size <= 8160) {
                  if (ip_total_length <= 1036) {
                   y += 1;
                  }
                  else {
                   if (ip_total_length <= 1096) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                 else {
                  if (tcp_window_size <= 11232) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 11360) {
                    y += 0;
                   }
                   else {
                    if (tcp_window_size <= 16416) {
                     if (tcp_window_size <= 16000) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                 }
                }
                else {
                 y += 0;
                }
               }
               else {
                y += 1;
               }
              }
             }
            }
            else {
             if (tcp_window_size <= 10272) {
              if (tcp_window_size <= 10144) {
               if (tcp_window_size <= 7808) {
                if (tcp_window_size <= 7712) {
                 y += 1;
                }
                else {
                 y += 1;
                }
               }
               else {
                if (tcp_window_size <= 7968) {
                 y += 1;
                }
                else {
                 if (tcp_window_size <= 8032) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 8544) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 8608) {
                    y += 0;
                   }
                   else {
                    if (tcp_window_size <= 8832) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 8960) {
                      y += 0;
                     }
                     else {
                      if (tcp_window_size <= 9056) {
                       y += 1;
                      }
                      else {
                       if (tcp_window_size <= 9216) {
                        if (tcp_window_size <= 9120) {
                         y += 1;
                        }
                        else {
                         y += 0;
                        }
                       }
                       else {
                        if (tcp_window_size <= 10080) {
                         if (tcp_window_size <= 10016) {
                          y += 1;
                         }
                         else {
                          y += 1;
                         }
                        }
                        else {
                         y += 1;
                        }
                       }
                      }
                     }
                    }
                   }
                  }
                 }
                }
               }
              }
              else {
               if (tcp_window_size <= 10208) {
                y += 0;
               }
               else {
                y += 0;
               }
              }
             }
             else {
              if (tcp_window_size <= 13152) {
               if (tcp_window_size <= 13088) {
                if (tcp_window_size <= 12384) {
                 if (tcp_window_size <= 11360) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 11424) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 11680) {
                    if (tcp_window_size <= 11616) {
                     y += 1;
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 12448) {
                  y += 1;
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                y += 0;
               }
              }
              else {
               if (tcp_window_size <= 20384) {
                if (tcp_window_size <= 18656) {
                 if (tcp_window_size <= 14496) {
                  if (tcp_window_size <= 14432) {
                   if (tcp_window_size <= 13664) {
                    if (tcp_window_size <= 13600) {
                     y += 1;
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 if (tcp_window_size <= 18720) {
                  y += 1;
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                if (tcp_window_size <= 20480) {
                 y += 1;
                }
                else {
                 y += 1;
                }
               }
              }
             }
            }
           }
           else {
            if (ip_total_length <= 1431) {
             y += 1;
            }
            else {
             if (tcp_window_size <= 21184) {
              y += 0;
             }
             else {
              if (tcp_window_size <= 21280) {
               y += 1;
              }
              else {
               y += 1;
              }
             }
            }
           }
          }
          else {
           y += 1;
          }
         }
        }
        else {
         if (ip_total_length <= 46) {
          y += 0;
         }
         else {
          if (tcp_ack_flag <= 0) {
           y += 1;
          }
          else {
           if (tcp_rst_flag <= 0) {
            if (tcp_fin_flag <= 0) {
             if (ip_total_length <= 1499) {
              if (tcp_window_size <= 30688) {
               if (tcp_window_size <= 30624) {
                if (ip_total_length <= 664) {
                 if (ip_total_length <= 663) {
                  if (tcp_window_size <= 25056) {
                   if (tcp_window_size <= 24992) {
                    y += 1;
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  if (tcp_window_size <= 27360) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 27904) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
                else {
                 y += 1;
                }
               }
               else {
                if (ip_total_length <= 1082) {
                 y += 1;
                }
                else {
                 y += 0;
                }
               }
              }
              else {
               if (tcp_window_size <= 41632) {
                if (ip_total_length <= 925) {
                 y += 1;
                }
                else {
                 if (ip_total_length <= 933) {
                  y += 0;
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                y += 1;
               }
              }
             }
             else {
              if (tcp_window_size <= 24352) {
               if (tcp_window_size <= 24256) {
                if (tcp_window_size <= 23584) {
                 y += 1;
                }
                else {
                 if (tcp_window_size <= 23648) {
                  y += 0;
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                y += 0;
               }
              }
              else {
               if (tcp_window_size <= 27040) {
                if (tcp_window_size <= 26944) {
                 y += 1;
                }
                else {
                 y += 1;
                }
               }
               else {
                if (tcp_window_size <= 43552) {
                 if (tcp_window_size <= 43488) {
                  if (tcp_window_size <= 34080) {
                   if (tcp_window_size <= 34016) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 y += 1;
                }
               }
              }
             }
            }
            else {
             y += 1;
            }
           }
           else {
            y += 1;
           }
          }
         }
        }
       }
      }
     }
    }
    else {
     y += 0;
    }
    if (ip_total_length <= 19) {
     y += 0;
    }
    else {
     if (tcp_fin_flag <= 0) {
      if (tcp_window_size <= 1045632) {
       if (ip_protocol <= 11) {
        if (tcp_window_size <= 129408) {
         if (ip_total_length <= 42) {
          if (tcp_rst_flag <= 0) {
           y += 0;
          }
          else {
           y += 1;
          }
         }
         else {
          if (ip_ttl <= 96) {
           if (tcp_syn_flag <= 0) {
            if (tcp_syn_flag <= 0) {
             y += 1;
            }
            else {
             if (tcp_window_size <= 7584) {
              if (tcp_window_size <= 6944) {
               if (tcp_window_size <= 6400) {
                y += 1;
               }
               else {
                if (ip_total_length <= 134) {
                 y += 1;
                }
                else {
                 if (ip_total_length <= 619) {
                  if (ip_total_length <= 615) {
                   if (ip_total_length <= 140) {
                    y += 0;
                   }
                   else {
                    if (ip_total_length <= 516) {
                     if (ip_total_length <= 241) {
                      y += 1;
                     }
                     else {
                      if (ip_total_length <= 257) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                    else {
                     if (ip_total_length <= 529) {
                      y += 0;
                     }
                     else {
                      if (ip_total_length <= 597) {
                       if (ip_total_length <= 558) {
                        y += 1;
                       }
                       else {
                        y += 0;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                  }
                  else {
                   y += 0;
                  }
                 }
                 else {
                  if (ip_total_length <= 712) {
                   if (ip_total_length <= 669) {
                    y += 1;
                   }
                   else {
                    if (ip_total_length <= 687) {
                     if (ip_total_length <= 686) {
                      if (ip_total_length <= 670) {
                       y += 1;
                      }
                      else {
                       if (ip_total_length <= 676) {
                        if (ip_total_length <= 675) {
                         y += 1;
                        }
                        else {
                         y += 0;
                        }
                       }
                       else {
                        y += 1;
                       }
                      }
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                  else {
                   if (ip_total_length <= 1173) {
                    if (ip_total_length <= 994) {
                     if (ip_total_length <= 714) {
                      if (ip_total_length <= 713) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                     else {
                      if (ip_total_length <= 884) {
                       y += 1;
                      }
                      else {
                       if (ip_total_length <= 916) {
                        y += 0;
                       }
                       else {
                        y += 1;
                       }
                      }
                     }
                    }
                    else {
                     if (ip_total_length <= 1143) {
                      if (ip_total_length <= 1043) {
                       if (ip_total_length <= 997) {
                        y += 0;
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       y += 0;
                      }
                     }
                     else {
                      if (ip_total_length <= 1168) {
                       y += 1;
                      }
                      else {
                       y += 0;
                      }
                     }
                    }
                   }
                   else {
                    if (ip_total_length <= 1433) {
                     if (ip_total_length <= 1254) {
                      if (ip_total_length <= 1253) {
                       y += 1;
                      }
                      else {
                       y += 0;
                      }
                     }
                     else {
                      if (ip_total_length <= 1305) {
                       y += 1;
                      }
                      else {
                       if (ip_total_length <= 1306) {
                        y += 0;
                       }
                       else {
                        y += 1;
                       }
                      }
                     }
                    }
                    else {
                     if (ip_total_length <= 1472) {
                      y += 0;
                     }
                     else {
                      if (ip_total_length <= 1495) {
                       y += 1;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                  }
                 }
                }
               }
              }
              else {
               if (ip_total_length <= 1495) {
                if (tcp_window_size <= 7488) {
                 if (ip_total_length <= 171) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 426) {
                   y += 0;
                  }
                  else {
                   if (ip_total_length <= 1002) {
                    y += 1;
                   }
                   else {
                    if (ip_total_length <= 1321) {
                     y += 0;
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                 }
                }
                else {
                 if (ip_total_length <= 470) {
                  y += 0;
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                if (tcp_window_size <= 7328) {
                 if (tcp_window_size <= 7264) {
                  if (tcp_window_size <= 7104) {
                   y += 0;
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  y += 0;
                 }
                }
                else {
                 if (tcp_window_size <= 7392) {
                  y += 1;
                 }
                 else {
                  y += 1;
                 }
                }
               }
              }
             }
             else {
              if (tcp_window_size <= 21344) {
               if (ip_total_length <= 1495) {
                if (ip_total_length <= 956) {
                 if (ip_total_length <= 434) {
                  if (ip_total_length <= 432) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 9216) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 if (ip_total_length <= 958) {
                  y += 0;
                 }
                 else {
                  if (ip_total_length <= 1086) {
                   if (tcp_window_size <= 8160) {
                    if (tcp_window_size <= 8032) {
                     y += 1;
                    }
                    else {
                     y += 0;
                    }
                   }
                   else {
                    if (tcp_window_size <= 14304) {
                     if (ip_total_length <= 1011) {
                      y += 1;
                     }
                     else {
                      if (ip_total_length <= 1021) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
               else {
                if (tcp_window_size <= 21088) {
                 if (tcp_window_size <= 10272) {
                  if (tcp_window_size <= 10144) {
                   if (tcp_window_size <= 7776) {
                    if (tcp_window_size <= 7712) {
                     y += 1;
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    if (tcp_window_size <= 8032) {
                     if (tcp_window_size <= 7968) {
                      y += 1;
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     if (tcp_window_size <= 8736) {
                      y += 1;
                     }
                     else {
                      if (tcp_window_size <= 8832) {
                       y += 0;
                      }
                      else {
                       if (tcp_window_size <= 8960) {
                        y += 1;
                       }
                       else {
                        if (tcp_window_size <= 10080) {
                         if (tcp_window_size <= 9056) {
                          y += 1;
                         }
                         else {
                          if (tcp_window_size <= 9184) {
                           if (tcp_window_size <= 9120) {
                            y += 1;
                           }
                           else {
                            y += 1;
                           }
                          }
                          else {
                           if (tcp_window_size <= 10016) {
                            y += 1;
                           }
                           else {
                            y += 1;
                           }
                          }
                         }
                        }
                        else {
                         y += 1;
                        }
                       }
                      }
                     }
                    }
                   }
                  }
                  else {
                   if (tcp_window_size <= 10208) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                 else {
                  if (tcp_window_size <= 13152) {
                   if (tcp_window_size <= 12960) {
                    if (tcp_window_size <= 12384) {
                     if (tcp_window_size <= 11680) {
                      if (tcp_window_size <= 11616) {
                       if (tcp_window_size <= 11424) {
                        if (tcp_window_size <= 11360) {
                         if (tcp_window_size <= 11168) {
                          y += 1;
                         }
                         else {
                          if (tcp_window_size <= 11232) {
                           y += 1;
                          }
                          else {
                           y += 1;
                          }
                         }
                        }
                        else {
                         y += 1;
                        }
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     if (tcp_window_size <= 12448) {
                      y += 1;
                     }
                     else {
                      y += 1;
                     }
                    }
                   }
                   else {
                    if (tcp_window_size <= 13024) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 13088) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                   }
                  }
                  else {
                   if (tcp_window_size <= 19360) {
                    if (tcp_window_size <= 19296) {
                     if (tcp_window_size <= 15840) {
                      if (tcp_window_size <= 13600) {
                       y += 1;
                      }
                      else {
                       if (tcp_window_size <= 13664) {
                        y += 1;
                       }
                       else {
                        if (tcp_window_size <= 15296) {
                         y += 1;
                        }
                        else {
                         if (tcp_window_size <= 15392) {
                          y += 1;
                         }
                         else {
                          y += 1;
                         }
                        }
                       }
                      }
                     }
                     else {
                      if (tcp_window_size <= 15936) {
                       y += 1;
                      }
                      else {
                       if (tcp_window_size <= 17472) {
                        if (tcp_window_size <= 17376) {
                         y += 1;
                        }
                        else {
                         y += 1;
                        }
                       }
                       else {
                        if (tcp_window_size <= 18624) {
                         y += 1;
                        }
                        else {
                         if (tcp_window_size <= 18720) {
                          y += 1;
                         }
                         else {
                          y += 1;
                         }
                        }
                       }
                      }
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 21184) {
                  y += 0;
                 }
                 else {
                  if (tcp_window_size <= 21280) {
                   y += 1;
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
              }
              else {
               if (tcp_window_size <= 25888) {
                if (tcp_window_size <= 25824) {
                 if (ip_total_length <= 1455) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 24288) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 24352) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                }
                else {
                 if (ip_total_length <= 1457) {
                  y += 1;
                 }
                 else {
                  y += 1;
                 }
                }
               }
               else {
                if (ip_total_length <= 1499) {
                 if (ip_total_length <= 933) {
                  if (ip_total_length <= 506) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 45120) {
                    if (ip_total_length <= 508) {
                     if (tcp_window_size <= 43296) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                 else {
                  if (tcp_window_size <= 36608) {
                   if (ip_total_length <= 936) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 37856) {
                  if (tcp_window_size <= 37792) {
                   if (tcp_window_size <= 33984) {
                    if (tcp_window_size <= 27040) {
                     if (tcp_window_size <= 26944) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    if (tcp_window_size <= 34080) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 36512) {
                      y += 1;
                     }
                     else {
                      if (tcp_window_size <= 36576) {
                       y += 1;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                  }
                  else {
                   y += 0;
                  }
                 }
                 else {
                  if (tcp_window_size <= 43552) {
                   if (tcp_window_size <= 43488) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
              }
             }
            }
           }
           else {
            if (ip_ttl <= 61) {
             y += 1;
            }
            else {
             if (tcp_window_size <= 35040) {
              if (tcp_window_size <= 5816) {
               y += 1;
              }
              else {
               if (ip_total_length <= 48) {
                y += 1;
               }
               else {
                y += 0;
               }
              }
             }
             else {
              y += 1;
             }
            }
           }
          }
          else {
           y += 0;
          }
         }
        }
        else {
         if (tcp_rst_flag <= 0) {
          if (ip_ttl <= 96) {
           y += 1;
          }
          else {
           y += 0;
          }
         }
         else {
          y += 1;
         }
        }
       }
       else {
        if (ip_ttl <= 32) {
         y += 0;
        }
        else {
         if (ip_total_length <= 72) {
          if (ip_total_length <= 60) {
           if (ip_total_length <= 59) {
            if (ip_total_length <= 58) {
             y += 0;
            }
            else {
             y += 0;
            }
           }
           else {
            y += 0;
           }
          }
          else {
           if (ip_total_length <= 62) {
            y += 1;
           }
           else {
            if (ip_total_length <= 70) {
             y += 0;
            }
            else {
             if (ip_total_length <= 71) {
              y += 1;
             }
             else {
              y += 0;
             }
            }
           }
          }
         }
         else {
          if (ip_total_length <= 177) {
           y += 1;
          }
          else {
           if (ip_total_length <= 294) {
            y += 0;
           }
           else {
            y += 1;
           }
          }
         }
        }
       }
      }
      else {
       if (tcp_window_size <= 1054208) {
        y += 0;
       }
       else {
        y += 1;
       }
      }
     }
     else {
      if (tcp_window_size <= 126464) {
       if (tcp_window_size <= 6944) {
        if (tcp_window_size <= 5856) {
         y += 1;
        }
        else {
         if (ip_total_length <= 46) {
          y += 0;
         }
         else {
          y += 1;
         }
        }
       }
       else {
        if (ip_total_length <= 46) {
         y += 0;
        }
        else {
         y += 1;
        }
       }
      }
      else {
       if (ip_total_length <= 46) {
        y += 0;
       }
       else {
        y += 1;
       }
      }
     }
    }
    if (tcp_window_size <= 1041920) {
     if (ip_total_length <= 19) {
      y += 0;
     }
     else {
      if (ip_total_length <= 42) {
       if (tcp_ack_flag <= 0) {
        y += 0;
       }
       else {
        if (tcp_window_size <= 2944) {
         y += 1;
        }
        else {
         y += 0;
        }
       }
      }
      else {
       if (ip_protocol <= 11) {
        if (ip_ttl <= 96) {
         if (ip_total_length <= 1469) {
          if (ip_ttl <= 61) {
           y += 1;
          }
          else {
           if (tcp_fin_flag <= 0) {
            if (tcp_syn_flag <= 0) {
             if (tcp_window_size <= 7584) {
              if (tcp_syn_flag <= 0) {
               y += 1;
              }
              else {
               if (ip_total_length <= 241) {
                if (tcp_window_size <= 7520) {
                 if (ip_total_length <= 139) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 140) {
                   y += 1;
                  }
                  else {
                   y += 1;
                  }
                 }
                }
                else {
                 y += 0;
                }
               }
               else {
                if (tcp_window_size <= 6368) {
                 y += 1;
                }
                else {
                 if (ip_total_length <= 619) {
                  if (ip_total_length <= 615) {
                   if (ip_total_length <= 306) {
                    if (tcp_window_size <= 7168) {
                     if (ip_total_length <= 272) {
                      if (ip_total_length <= 257) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    if (tcp_window_size <= 7072) {
                     if (ip_total_length <= 516) {
                      y += 1;
                     }
                     else {
                      if (ip_total_length <= 529) {
                       y += 0;
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                  else {
                   y += 0;
                  }
                 }
                 else {
                  if (tcp_window_size <= 7072) {
                   if (ip_total_length <= 712) {
                    if (ip_total_length <= 669) {
                     y += 1;
                    }
                    else {
                     if (ip_total_length <= 676) {
                      if (ip_total_length <= 675) {
                       if (ip_total_length <= 670) {
                        y += 1;
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       y += 0;
                      }
                     }
                     else {
                      if (ip_total_length <= 690) {
                       if (ip_total_length <= 689) {
                        y += 1;
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                   else {
                    if (ip_total_length <= 715) {
                     if (ip_total_length <= 713) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     if (ip_total_length <= 1177) {
                      if (ip_total_length <= 874) {
                       y += 1;
                      }
                      else {
                       if (ip_total_length <= 915) {
                        if (ip_total_length <= 879) {
                         y += 0;
                        }
                        else {
                         if (ip_total_length <= 885) {
                          y += 1;
                         }
                         else {
                          y += 0;
                         }
                        }
                       }
                       else {
                        if (ip_total_length <= 994) {
                         y += 1;
                        }
                        else {
                         if (ip_total_length <= 997) {
                          y += 0;
                         }
                         else {
                          if (ip_total_length <= 1168) {
                           if (ip_total_length <= 1143) {
                            if (ip_total_length <= 1044) {
                             y += 1;
                            }
                            else {
                             y += 0;
                            }
                           }
                           else {
                            y += 1;
                           }
                          }
                          else {
                           y += 0;
                          }
                         }
                        }
                       }
                      }
                     }
                     else {
                      if (ip_total_length <= 1254) {
                       if (ip_total_length <= 1251) {
                        y += 1;
                       }
                       else {
                        y += 0;
                       }
                      }
                      else {
                       y += 1;
                      }
                     }
                    }
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
              }
             }
             else {
              if (tcp_window_size <= 8352) {
               if (tcp_window_size <= 8096) {
                y += 1;
               }
               else {
                if (tcp_window_size <= 8160) {
                 if (ip_total_length <= 769) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 1145) {
                   y += 0;
                  }
                  else {
                   y += 1;
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 8288) {
                  y += 1;
                 }
                 else {
                  if (ip_total_length <= 563) {
                   if (ip_total_length <= 243) {
                    y += 1;
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
              }
              else {
               if (ip_total_length <= 858) {
                if (tcp_window_size <= 45088) {
                 if (ip_total_length <= 664) {
                  if (ip_total_length <= 663) {
                   if (ip_total_length <= 507) {
                    if (ip_total_length <= 505) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 43328) {
                      y += 1;
                     }
                     else {
                      y += 0;
                     }
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   if (tcp_window_size <= 27360) {
                    y += 1;
                   }
                   else {
                    if (tcp_window_size <= 27904) {
                     y += 0;
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 y += 1;
                }
               }
               else {
                if (ip_total_length <= 859) {
                 if (tcp_window_size <= 16032) {
                  y += 1;
                 }
                 else {
                  y += 0;
                 }
                }
                else {
                 if (ip_total_length <= 1179) {
                  if (ip_total_length <= 1178) {
                   if (ip_total_length <= 1114) {
                    if (tcp_window_size <= 14304) {
                     if (tcp_window_size <= 13760) {
                      if (tcp_window_size <= 11232) {
                       y += 1;
                      }
                      else {
                       if (tcp_window_size <= 11424) {
                        y += 0;
                       }
                       else {
                        y += 1;
                       }
                      }
                     }
                     else {
                      y += 0;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    if (ip_total_length <= 1115) {
                     if (tcp_window_size <= 40256) {
                      y += 0;
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                  else {
                   if (tcp_window_size <= 47584) {
                    y += 0;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                 else {
                  if (tcp_window_size <= 12928) {
                   if (tcp_window_size <= 12384) {
                    y += 1;
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
              }
             }
            }
            else {
             if (ip_total_length <= 56) {
              y += 0;
             }
             else {
              y += 1;
             }
            }
           }
           else {
            y += 1;
           }
          }
         }
         else {
          if (ip_total_length <= 1470) {
           if (tcp_window_size <= 35712) {
            y += 0;
           }
           else {
            y += 1;
           }
          }
          else {
           if (ip_total_length <= 1499) {
            y += 1;
           }
           else {
            if (tcp_window_size <= 21376) {
             if (tcp_window_size <= 21088) {
              if (tcp_window_size <= 10272) {
               if (tcp_window_size <= 10144) {
                if (tcp_window_size <= 7392) {
                 if (tcp_window_size <= 6944) {
                  if (tcp_window_size <= 6368) {
                   y += 1;
                  }
                  else {
                   y += 1;
                  }
                 }
                 else {
                  if (tcp_window_size <= 7328) {
                   if (tcp_window_size <= 7136) {
                    if (tcp_window_size <= 7008) {
                     y += 0;
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 8736) {
                  if (tcp_window_size <= 8032) {
                   if (tcp_window_size <= 7968) {
                    if (tcp_window_size <= 7776) {
                     if (tcp_window_size <= 7712) {
                      y += 1;
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     y += 1;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   if (tcp_window_size <= 8608) {
                    if (tcp_window_size <= 8544) {
                     y += 1;
                    }
                    else {
                     y += 0;
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                 else {
                  if (tcp_window_size <= 8960) {
                   if (tcp_window_size <= 8832) {
                    y += 0;
                   }
                   else {
                    y += 0;
                   }
                  }
                  else {
                   if (tcp_window_size <= 9056) {
                    y += 1;
                   }
                   else {
                    if (tcp_window_size <= 9216) {
                     if (tcp_window_size <= 9120) {
                      y += 1;
                     }
                     else {
                      y += 1;
                     }
                    }
                    else {
                     if (tcp_window_size <= 10080) {
                      if (tcp_window_size <= 9952) {
                       y += 1;
                      }
                      else {
                       y += 1;
                      }
                     }
                     else {
                      y += 1;
                     }
                    }
                   }
                  }
                 }
                }
               }
               else {
                if (tcp_window_size <= 10208) {
                 y += 0;
                }
                else {
                 y += 1;
                }
               }
              }
              else {
               if (tcp_window_size <= 13152) {
                if (tcp_window_size <= 13088) {
                 if (tcp_window_size <= 12960) {
                  if (tcp_window_size <= 12384) {
                   if (tcp_window_size <= 11616) {
                    y += 1;
                   }
                   else {
                    if (tcp_window_size <= 11680) {
                     y += 1;
                    }
                    else {
                     y += 1;
                    }
                   }
                  }
                  else {
                   if (tcp_window_size <= 12448) {
                    y += 1;
                   }
                   else {
                    y += 1;
                   }
                  }
                 }
                 else {
                  if (tcp_window_size <= 13024) {
                   y += 1;
                  }
                  else {
                   y += 1;
                  }
                 }
                }
                else {
                 y += 0;
                }
               }
               else {
                if (tcp_window_size <= 15328) {
                 y += 1;
                }
                else {
                 if (tcp_window_size <= 15392) {
                  y += 1;
                 }
                 else {
                  if (tcp_window_size <= 19360) {
                   if (tcp_window_size <= 19296) {
                    if (tcp_window_size <= 15840) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 15936) {
                      y += 1;
                     }
                     else {
                      if (tcp_window_size <= 17472) {
                       if (tcp_window_size <= 17376) {
                        y += 1;
                       }
                       else {
                        y += 1;
                       }
                      }
                      else {
                       if (tcp_window_size <= 18656) {
                        y += 1;
                       }
                       else {
                        if (tcp_window_size <= 18720) {
                         y += 1;
                        }
                        else {
                         y += 1;
                        }
                       }
                      }
                     }
                    }
                   }
                   else {
                    y += 1;
                   }
                  }
                  else {
                   y += 1;
                  }
                 }
                }
               }
              }
             }
             else {
              if (tcp_window_size <= 21184) {
               y += 0;
              }
              else {
               if (tcp_window_size <= 21280) {
                y += 1;
               }
               else {
                y += 1;
               }
              }
             }
            }
            else {
             if (tcp_window_size <= 27104) {
              if (tcp_window_size <= 26944) {
               if (tcp_window_size <= 24288) {
                y += 1;
               }
               else {
                if (tcp_window_size <= 24352) {
                 y += 0;
                }
                else {
                 y += 1;
                }
               }
              }
              else {
               if (tcp_window_size <= 27040) {
                y += 0;
               }
               else {
                y += 1;
               }
              }
             }
             else {
              if (tcp_window_size <= 43552) {
               if (tcp_window_size <= 43488) {
                if (tcp_window_size <= 36576) {
                 if (tcp_window_size <= 36512) {
                  if (tcp_window_size <= 30432) {
                   y += 1;
                  }
                  else {
                   if (tcp_window_size <= 30496) {
                    y += 1;
                   }
                   else {
                    if (tcp_window_size <= 34016) {
                     y += 1;
                    }
                    else {
                     if (tcp_window_size <= 34080) {
                      y += 1;
                     }
                     else {
                      y += 1;
                     }
                    }
                   }
                  }
                 }
                 else {
                  y += 1;
                 }
                }
                else {
                 y += 1;
                }
               }
               else {
                y += 1;
               }
              }
              else {
               y += 1;
              }
             }
            }
           }
          }
         }
        }
        else {
         y += 0;
        }
       }
       else {
        if (ip_ttl <= 32) {
         y += 0;
        }
        else {
         if (ip_total_length <= 72) {
          if (ip_total_length <= 58) {
           y += 0;
          }
          else {
           if (ip_total_length <= 71) {
            if (ip_total_length <= 60) {
             if (ip_total_length <= 59) {
              y += 1;
             }
             else {
              y += 0;
             }
            }
            else {
             if (ip_total_length <= 62) {
              y += 1;
             }
             else {
              if (ip_total_length <= 70) {
               if (ip_total_length <= 66) {
                y += 0;
               }
               else {
                y += 0;
               }
              }
              else {
               y += 1;
              }
             }
            }
           }
           else {
            y += 0;
           }
          }
         }
         else {
          y += 1;
         }
        }
       }
      }
     }
    }
    else {
     if (tcp_window_size <= 1054208) {
      y += 0;
     }
     else {
      y += 1;
     }
    }

    y = (y > 2);


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
