# SkimXDP

SkimXDP (skX) is a powerful tool that combines the capabilities of two technologies: scikit-learn, a widely-used machine learning library, and XDP (eXpress Data Path), a technology used for packet filtering in Linux. With SkimXDP, you can enhance your network's security by creating custom packet filters using machine learning models. This document provides an overview of the main components and how to use the SkimXDP application.


> **Note**
> Please keep in mind that this project is a proof-of-concept.

## Install

```bash
git clone https://github.com/Koukyosyumei/SkimXDP.git
cd SkimXDP
pip install -e .
```

## Usage

### Command Line Interface (CLI)

Here's an example of how to use SkimXDP from the command line:

```bash
skX -m model/tree.pkl -d outputs -f skX_tree -i lo
```

Arguments for `skX`

- `-m` or `--path_to_model_and_featurenames`: Specify the path to the pre-trained model (in pickle format) and the list of feature names.
- `-d` or `--dir_to_save_outputs`: Set the directory path where all the output files will be saved.
- `-f` or `--file_name`: Define the name for the output binary.
- `-i` or `--interface`: Specify the name of the network interface.
- `-s` or `--stop_after_generation_of_sources`: Optionally, stop execution after generating source code.
- `-c` or `--stop_after_compile`: Optionally, stop execution after compiling the code.
- `--threshod`: Threshold to being predicted as positive (effective for Linear Models and MLP)
- `precision`: Precision for quantization (effective for Linear Models and MLP)
- `--tolerance`: Set the tolerance level for checking the existence of the compiled object before attaching it to the network interface.


### Training Example

To use `skX`, you need the pickle file of a pre-trained classifier and its associated feature names. You can find a demonstration of how to train classifiers in the [demo/train.py](demo/train.py) file.


### Available Features

You can currently use the following features as the input to the claffier.

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

### Supported Models

`skX` currently supports the following machine learning algorithms

- sklearn.tree.DecisionTreeClassifier
- sklearn.ensemble.RandomForestClassifier
- sklearn.linear_model.LogisticRegression
- sklearn.linear_model.RidgeClassifier
- sklearn.neural_network.MLPClassifier

## Worlflow

In a nutshell, here's how SkimXDP works:


```
1. First, `skX` loads the pickle of a pair of pre-trained machine learning model and feature names from the specified file path. 
2. Second, `skX` generates C code for the packet filter, incorporating the loaded model.
3. Then, generated C code is saved to a file in the specified output directory, and helper headers are also saved.
4. Next, `skX` compiles the generated C code into a binary object suitable for packet filtering (default compiler is clang).
5. Finally, the compiled object is attached to the network interface, enabling packet filtering.
```

## Tips

- To check the status of a network interface, you can use the following command:

```bash
ip link show dev `name_of_interface`
```

- To remove the packet filter from an interface, you can use the following command (replace name_of_interface with the actual interface name):

```bash
sudo ip link set dev `name_of_interface` xdp off
```

## Reference

This project draws inspiration from the following research papers and tools:

- Takanori Hara, Masahiro Sasabe, On Practicality of Kernel Packet Processing Empowered by Lightweight Neural Network and Decision Tree, Proc. of 14th International Conference on Network of the Future, October 2023.

- Bachl, Maximilian, Joachim Fabini, and Tanja Zseby. "A flow-based IDS using Machine Learning in eBPF." arXiv preprint arXiv:2102.09980 (2021).

- de Carvalho Bertoli, Gustavo, et al. "Evaluation of netfilter and eBPF/XDP to filter TCP flag-based probing attacks." Proceedings of XXII symposium on operational applications in defense area (SIGE). 2020.

- [motus/bpf-ml](https://github.com/motus/bpf-ml)
