# SkimXDP

SkimXDP (skX) is a powerful tool that combines the capabilities of scikit-learn, a popular machine learning library, and XDP (eXpress Data Path), a technology for packet filtering in Linux. With SkimXDP, you can enhance your network's security by creating custom packet filters using machine learning models. This document explains the main components and usage of the SkimXDP app.

> **Note**
> Please use this tool only for experimental usage.

## Usage 

Command-line Arguments: Run `skX` command, specifying various options using the following arguments:

```
-m or --path_to_model_and_featurenames: Provide the path to the pickled pre-trained model and the list of feature names.
-d or --dir_to_save_outputs: Set the path to the directory where all outputs will be saved.
-f or --file_name: Specify the name of the output binary.
-i or --interface: Define the name of the network interface.
-s or --stop_after_generation_of_sources: Optionally, stop execution after generating source code.
-c or --stop_after_compile: Optionally, stop execution after compiling the code.
-t or --tolerance: Set the tolerance level for checking the existence of the compiled object before attaching it to the network interface.
```

To put it simply, `skX` works as follows:

```
1. First, `skX` loads the pickle of a pair of pre-trained machine learning model and feature names from the specified file path. 
2. Second, `skX` generates C code for the packet filter, incorporating the loaded model.
3. Then, generated C code is saved to a file in the specified output directory, and helper headers are also saved.
4. Next, `skX` compiles the generated C code into a binary object suitable for packet filtering (default compiler is clang).
5. Finally, the compiled object is attached to the network interface, enabling packet filtering.
```

## Available Features

You can use the following features as the input to the claffier.

```
# IPv4 Header
unsigned int ip_ihl;
unsigned int ip_version;
int ip_preference;
int ip_dscp;
uint16_t ip_total_length;
uint16_t ip_frag_offset;
uint8_t ip_ttl;
uint8_t ip_protocol;

# TCP Header
uint16_t source_port
uint16_t dest_port
unsigned int tcp_sequence_num
unsigned int tcp_ack_num
uint16_t tcp_window_size
uint16_t tcp_urgent_pointer
uint16_t tcp_cwr_flag
uint16_t tcp_ece_flag
uint16_t tcp_urg_flag
uint16_t tcp_ack_flag
uint16_t tcp_psh_flag
uint16_t tcp_rst_flag
uint16_t tcp_syn_flag
uint16_t tcp_fin_flag
```

## Tips

- check

```bash
ip link show dev lo
```

- remove

```bash
sudo ip link set dev `name_of_interface` xdp off
```

## Reference

This project is inspired by the following amazing papers and tools.
