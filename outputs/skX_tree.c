
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
    if (ip_ttl <= 96) {
     if (ip_ttl <= 26) {
      if (ip_ttl <= 8) {
       y = 0;
      }
      else {
       y = 0;
      }
     }
     else {
      if (tcp_window_size <= 7584) {
       if (tcp_window_size <= 5832) {
        if (ip_protocol <= 11) {
         y = 1;
        }
        else {
         if (ip_total_length <= 72) {
          if (ip_total_length <= 58) {
           y = 0;
          }
          else {
           if (ip_total_length <= 70) {
            if (ip_total_length <= 62) {
             if (ip_total_length <= 60) {
              if (ip_total_length <= 59) {
               y = 1;
              }
              else {
               y = 0;
              }
             }
             else {
              y = 1;
             }
            }
            else {
             if (ip_total_length <= 66) {
              y = 0;
             }
             else {
              y = 0;
             }
            }
           }
           else {
            if (ip_total_length <= 71) {
             y = 1;
            }
            else {
             y = 0;
            }
           }
          }
         }
         else {
          if (ip_total_length <= 177) {
           y = 1;
          }
          else {
           if (ip_total_length <= 294) {
            y = 0;
           }
           else {
            y = 1;
           }
          }
         }
        }
       }
       else {
        if (ip_total_length <= 42) {
         y = 0;
        }
        else {
         if (tcp_window_size <= 5864) {
          if (ip_total_length <= 48) {
           y = 1;
          }
          else {
           y = 0;
          }
         }
         else {
          if (tcp_sequence_num <= 130802) {
           if (tcp_window_size <= 6944) {
            if (tcp_ack_num <= 227) {
             if (ip_total_length <= 713) {
              if (tcp_ack_num <= 206) {
               if (tcp_sequence_num <= 1114) {
                if (ip_total_length <= 341) {
                 y = 1;
                }
                else {
                 if (ip_total_length <= 625) {
                  if (ip_total_length <= 558) {
                   if (ip_total_length <= 529) {
                    y = 0;
                   }
                   else {
                    y = 1;
                   }
                  }
                  else {
                   y = 0;
                  }
                 }
                 else {
                  if (ip_total_length <= 669) {
                   y = 1;
                  }
                  else {
                   if (tcp_ack_num <= 162) {
                    y = 0;
                   }
                   else {
                    if (tcp_ack_num <= 175) {
                     if (ip_total_length <= 683) {
                      y = 1;
                     }
                     else {
                      y = 0;
                     }
                    }
                    else {
                     y = 1;
                    }
                   }
                  }
                 }
                }
               }
               else {
                if (tcp_ack_num <= 113) {
                 y = 1;
                }
                else {
                 y = 0;
                }
               }
              }
              else {
               if (ip_total_length <= 334) {
                y = 1;
               }
               else {
                if (ip_total_length <= 658) {
                 y = 0;
                }
                else {
                 y = 1;
                }
               }
              }
             }
             else {
              if (tcp_ack_num <= 173) {
               if (tcp_ack_num <= 150) {
                y = 1;
               }
               else {
                y = 0;
               }
              }
              else {
               y = 1;
              }
             }
            }
            else {
             if (tcp_ack_num <= 500) {
              y = 1;
             }
             else {
              if (tcp_ack_num <= 516) {
               if (tcp_sequence_num <= 3921) {
                if (ip_total_length <= 675) {
                 y = 1;
                }
                else {
                 if (ip_total_length <= 1300) {
                  if (tcp_sequence_num <= 1449) {
                   y = 0;
                  }
                  else {
                   y = 1;
                  }
                 }
                 else {
                  if (tcp_ack_num <= 509) {
                   y = 1;
                  }
                  else {
                   if (tcp_sequence_num <= 725) {
                    y = 1;
                   }
                   else {
                    y = 1;
                   }
                  }
                 }
                }
               }
               else {
                y = 0;
               }
              }
              else {
               y = 1;
              }
             }
            }
           }
           else {
            if (tcp_ack_num <= 557) {
             y = 0;
            }
            else {
             if (ip_total_length <= 1495) {
              if (tcp_window_size <= 7520) {
               if (tcp_sequence_num <= 2909) {
                y = 1;
               }
               else {
                if (tcp_sequence_num <= 2987) {
                 y = 0;
                }
                else {
                 y = 1;
                }
               }
              }
              else {
               if (tcp_ack_num <= 845) {
                y = 0;
               }
               else {
                y = 1;
               }
              }
             }
             else {
              if (tcp_ack_num <= 768) {
               if (tcp_window_size <= 7072) {
                y = 1;
               }
               else {
                if (tcp_sequence_num <= 1455) {
                 if (tcp_ack_num <= 649) {
                  y = 0;
                 }
                 else {
                  if (tcp_sequence_num <= 725) {
                   if (tcp_ack_num <= 733) {
                    y = 0;
                   }
                   else {
                    y = 1;
                   }
                  }
                  else {
                   y = 1;
                  }
                 }
                }
                else {
                 y = 0;
                }
               }
              }
              else {
               y = 1;
              }
             }
            }
           }
          }
          else {
           y = 0;
          }
         }
        }
       }
      }
      else {
       if (ip_total_length <= 46) {
        y = 0;
       }
       else {
        if (tcp_sequence_num <= 430940) {
         if (tcp_window_size <= 25056) {
          if (tcp_sequence_num <= 66173) {
           if (tcp_window_size <= 24992) {
            if (tcp_sequence_num <= 53921) {
             if (ip_total_length <= 1495) {
              if (ip_total_length <= 956) {
               if (tcp_window_size <= 8352) {
                if (tcp_window_size <= 8288) {
                 y = 1;
                }
                else {
                 if (tcp_ack_num <= 1234) {
                  y = 0;
                 }
                 else {
                  y = 1;
                 }
                }
               }
               else {
                y = 1;
               }
              }
              else {
               if (ip_total_length <= 958) {
                if (tcp_sequence_num <= 29337) {
                 y = 1;
                }
                else {
                 y = 0;
                }
               }
               else {
                if (ip_total_length <= 1116) {
                 if (ip_total_length <= 1111) {
                  if (ip_total_length <= 1009) {
                   y = 1;
                  }
                  else {
                   if (ip_total_length <= 1021) {
                    y = 0;
                   }
                   else {
                    if (tcp_sequence_num <= 1273) {
                     y = 0;
                    }
                    else {
                     y = 1;
                    }
                   }
                  }
                 }
                 else {
                  y = 0;
                 }
                }
                else {
                 if (ip_total_length <= 1217) {
                  if (ip_total_length <= 1216) {
                   y = 1;
                  }
                  else {
                   y = 0;
                  }
                 }
                 else {
                  if (tcp_sequence_num <= 27299) {
                   y = 1;
                  }
                  else {
                   if (tcp_sequence_num <= 27308) {
                    y = 0;
                   }
                   else {
                    y = 1;
                   }
                  }
                 }
                }
               }
              }
             }
             else {
              if (tcp_ack_num <= 388) {
               if (tcp_ack_num <= 362) {
                y = 1;
               }
               else {
                y = 0;
               }
              }
              else {
               if (tcp_window_size <= 7776) {
                if (tcp_ack_num <= 944) {
                 y = 1;
                }
                else {
                 if (tcp_ack_num <= 962) {
                  if (tcp_ack_num <= 947) {
                   y = 0;
                  }
                  else {
                   if (tcp_sequence_num <= 1449) {
                    y = 0;
                   }
                   else {
                    y = 1;
                   }
                  }
                 }
                 else {
                  y = 1;
                 }
                }
               }
               else {
                if (tcp_window_size <= 15392) {
                 if (tcp_window_size <= 15328) {
                  if (tcp_sequence_num <= 34622) {
                   if (tcp_ack_num <= 2756) {
                    if (tcp_sequence_num <= 31165) {
                     if (tcp_sequence_num <= 5581) {
                      y = 1;
                     }
                     else {
                      if (tcp_sequence_num <= 5637) {
                       y = 0;
                      }
                      else {
                       if (tcp_window_size <= 8032) {
                        if (tcp_window_size <= 7968) {
                         y = 1;
                        }
                        else {
                         if (tcp_ack_num <= 1044) {
                          y = 0;
                         }
                         else {
                          y = 1;
                         }
                        }
                       }
                       else {
                        if (tcp_window_size <= 10272) {
                         if (tcp_window_size <= 10208) {
                          if (tcp_ack_num <= 1453) {
                           if (tcp_sequence_num <= 6732) {
                            if (tcp_sequence_num <= 6714) {
                             y = 1;
                            }
                            else {
                             y = 0;
                            }
                           }
                           else {
                            y = 1;
                           }
                          }
                          else {
                           if (tcp_ack_num <= 1455) {
                            if (tcp_sequence_num <= 12363) {
                             y = 1;
                            }
                            else {
                             y = 0;
                            }
                           }
                           else {
                            if (tcp_window_size <= 8800) {
                             y = 1;
                            }
                            else {
                             if (tcp_window_size <= 8960) {
                              if (tcp_sequence_num <= 14382) {
                               y = 1;
                              }
                              else {
                               y = 0;
                              }
                             }
                             else {
                              if (tcp_sequence_num <= 14917) {
                               if (tcp_sequence_num <= 12772) {
                                y = 1;
                               }
                               else {
                                y = 0;
                               }
                              }
                              else {
                               y = 1;
                              }
                             }
                            }
                           }
                          }
                         }
                         else {
                          if (tcp_ack_num <= 2190) {
                           y = 0;
                          }
                          else {
                           y = 1;
                          }
                         }
                        }
                        else {
                         if (tcp_sequence_num <= 8872) {
                          if (tcp_sequence_num <= 8813) {
                           y = 1;
                          }
                          else {
                           y = 0;
                          }
                         }
                         else {
                          y = 1;
                         }
                        }
                       }
                      }
                     }
                    }
                    else {
                     if (tcp_sequence_num <= 31186) {
                      y = 0;
                     }
                     else {
                      y = 1;
                     }
                    }
                   }
                   else {
                    if (tcp_ack_num <= 2757) {
                     y = 0;
                    }
                    else {
                     if (tcp_ack_num <= 2760) {
                      if (tcp_sequence_num <= 7788) {
                       y = 1;
                      }
                      else {
                       if (tcp_sequence_num <= 13772) {
                        y = 0;
                       }
                       else {
                        y = 1;
                       }
                      }
                     }
                     else {
                      if (tcp_sequence_num <= 19346) {
                       y = 1;
                      }
                      else {
                       if (tcp_sequence_num <= 19590) {
                        y = 0;
                       }
                       else {
                        if (tcp_ack_num <= 3331) {
                         y = 1;
                        }
                        else {
                         if (tcp_ack_num <= 3525) {
                          y = 0;
                         }
                         else {
                          y = 1;
                         }
                        }
                       }
                      }
                     }
                    }
                   }
                  }
                  else {
                   if (tcp_sequence_num <= 34727) {
                    y = 0;
                   }
                   else {
                    if (tcp_window_size <= 8128) {
                     if (tcp_window_size <= 7968) {
                      y = 1;
                     }
                     else {
                      y = 0;
                     }
                    }
                    else {
                     if (tcp_ack_num <= 1520) {
                      y = 1;
                     }
                     else {
                      if (tcp_ack_num <= 1682) {
                       y = 0;
                      }
                      else {
                       if (tcp_ack_num <= 3431) {
                        y = 1;
                       }
                       else {
                        if (tcp_ack_num <= 3460) {
                         y = 0;
                        }
                        else {
                         if (tcp_sequence_num <= 39179) {
                          if (tcp_sequence_num <= 37800) {
                           y = 1;
                          }
                          else {
                           y = 0;
                          }
                         }
                         else {
                          if (tcp_sequence_num <= 44346) {
                           if (tcp_sequence_num <= 44051) {
                            y = 1;
                           }
                           else {
                            y = 0;
                           }
                          }
                          else {
                           y = 1;
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
                  if (tcp_sequence_num <= 26092) {
                   y = 1;
                  }
                  else {
                   y = 0;
                  }
                 }
                }
                else {
                 if (tcp_window_size <= 24288) {
                  y = 1;
                 }
                 else {
                  if (tcp_window_size <= 24352) {
                   if (tcp_sequence_num <= 33623) {
                    y = 1;
                   }
                   else {
                    y = 0;
                   }
                  }
                  else {
                   y = 1;
                  }
                 }
                }
               }
              }
             }
            }
            else {
             if (tcp_sequence_num <= 53962) {
              y = 0;
             }
             else {
              if (tcp_window_size <= 24192) {
               if (tcp_ack_num <= 5444) {
                y = 1;
               }
               else {
                if (tcp_ack_num <= 5472) {
                 y = 0;
                }
                else {
                 if (ip_total_length <= 1312) {
                  y = 1;
                 }
                 else {
                  if (tcp_ack_num <= 6114) {
                   y = 1;
                  }
                  else {
                   if (tcp_window_size <= 19264) {
                    y = 0;
                   }
                   else {
                    if (tcp_window_size <= 20800) {
                     y = 1;
                    }
                    else {
                     if (tcp_ack_num <= 7359) {
                      y = 0;
                     }
                     else {
                      y = 1;
                     }
                    }
                   }
                  }
                 }
                }
               }
              }
              else {
               if (tcp_window_size <= 24384) {
                y = 0;
               }
               else {
                y = 1;
               }
              }
             }
            }
           }
           else {
            if (tcp_sequence_num <= 7445) {
             y = 0;
            }
            else {
             y = 1;
            }
           }
          }
          else {
           if (tcp_window_size <= 10240) {
            if (tcp_window_size <= 9024) {
             y = 1;
            }
            else {
             y = 0;
            }
           }
           else {
            if (tcp_ack_num <= 7343) {
             if (tcp_window_size <= 13152) {
              if (tcp_window_size <= 12992) {
               if (tcp_window_size <= 12320) {
                y = 1;
               }
               else {
                if (tcp_sequence_num <= 114049) {
                 y = 0;
                }
                else {
                 y = 1;
                }
               }
              }
              else {
               y = 0;
              }
             }
             else {
              if (tcp_sequence_num <= 70119) {
               if (tcp_ack_num <= 6420) {
                y = 1;
               }
               else {
                y = 0;
               }
              }
              else {
               if (tcp_ack_num <= 6234) {
                if (tcp_window_size <= 15936) {
                 if (tcp_ack_num <= 4911) {
                  y = 1;
                 }
                 else {
                  if (tcp_sequence_num <= 94847) {
                   y = 1;
                  }
                  else {
                   y = 0;
                  }
                 }
                }
                else {
                 y = 1;
                }
               }
               else {
                if (tcp_ack_num <= 6264) {
                 y = 0;
                }
                else {
                 if (tcp_sequence_num <= 75920) {
                  if (tcp_sequence_num <= 74472) {
                   y = 1;
                  }
                  else {
                   y = 0;
                  }
                 }
                 else {
                  y = 1;
                 }
                }
               }
              }
             }
            }
            else {
             if (tcp_ack_num <= 7363) {
              y = 0;
             }
             else {
              if (tcp_window_size <= 24256) {
               if (tcp_sequence_num <= 88113) {
                if (tcp_sequence_num <= 86665) {
                 y = 1;
                }
                else {
                 y = 0;
                }
               }
               else {
                y = 1;
               }
              }
              else {
               if (tcp_window_size <= 24352) {
                y = 0;
               }
               else {
                y = 1;
               }
              }
             }
            }
           }
          }
         }
         else {
          if (tcp_window_size <= 45088) {
           if (tcp_sequence_num <= 123289) {
            if (tcp_window_size <= 45024) {
             if (tcp_sequence_num <= 103609) {
              if (tcp_ack_num <= 11454) {
               if (tcp_sequence_num <= 81985) {
                y = 1;
               }
               else {
                if (tcp_sequence_num <= 81987) {
                 y = 0;
                }
                else {
                 y = 1;
                }
               }
              }
              else {
               if (tcp_ack_num <= 11455) {
                y = 0;
               }
               else {
                y = 1;
               }
              }
             }
             else {
              if (tcp_sequence_num <= 103795) {
               y = 0;
              }
              else {
               y = 1;
              }
             }
            }
            else {
             if (tcp_sequence_num <= 60742) {
              y = 1;
             }
             else {
              if (tcp_ack_num <= 13921) {
               y = 1;
              }
              else {
               y = 0;
              }
             }
            }
           }
           else {
            if (tcp_sequence_num <= 123498) {
             y = 0;
            }
            else {
             if (tcp_sequence_num <= 185561) {
              if (tcp_sequence_num <= 185454) {
               if (ip_total_length <= 1209) {
                if (ip_total_length <= 1144) {
                 if (tcp_ack_num <= 15867) {
                  if (tcp_window_size <= 27904) {
                   if (tcp_window_size <= 27360) {
                    y = 1;
                   }
                   else {
                    y = 0;
                   }
                  }
                  else {
                   y = 1;
                  }
                 }
                 else {
                  if (ip_total_length <= 490) {
                   y = 1;
                  }
                  else {
                   y = 0;
                  }
                 }
                }
                else {
                 y = 0;
                }
               }
               else {
                if (tcp_sequence_num <= 153470) {
                 if (tcp_sequence_num <= 153052) {
                  if (tcp_sequence_num <= 149653) {
                   if (tcp_ack_num <= 11369) {
                    y = 1;
                   }
                   else {
                    if (tcp_ack_num <= 11400) {
                     y = 0;
                    }
                    else {
                     if (tcp_window_size <= 34400) {
                      if (tcp_window_size <= 33728) {
                       y = 1;
                      }
                      else {
                       y = 0;
                      }
                     }
                     else {
                      y = 1;
                     }
                    }
                   }
                  }
                  else {
                   if (tcp_ack_num <= 8500) {
                    if (tcp_ack_num <= 7798) {
                     y = 1;
                    }
                    else {
                     y = 0;
                    }
                   }
                   else {
                    y = 1;
                   }
                  }
                 }
                 else {
                  y = 0;
                 }
                }
                else {
                 y = 1;
                }
               }
              }
              else {
               y = 0;
              }
             }
             else {
              y = 1;
             }
            }
           }
          }
          else {
           if (tcp_window_size <= 48416) {
            if (tcp_window_size <= 48352) {
             y = 1;
            }
            else {
             if (tcp_ack_num <= 18363) {
              y = 0;
             }
             else {
              y = 1;
             }
            }
           }
           else {
            y = 1;
           }
          }
         }
        }
        else {
         if (tcp_window_size <= 21344) {
          if (tcp_window_size <= 20992) {
           if (tcp_ack_num <= 2471) {
            if (tcp_ack_num <= 2043) {
             y = 1;
            }
            else {
             y = 0;
            }
           }
           else {
            y = 1;
           }
          }
          else {
           y = 0;
          }
         }
         else {
          y = 1;
         }
        }
       }
      }
     }
    }
    else {
     y = 0;
    }


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
