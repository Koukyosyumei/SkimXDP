import argparse
import subprocess
import os
import pickle
import time

from .exporter import export_clf_to_header
from .template import template_program, helper_header, helper_header_name


def add_args(parser):
    """Add arguments to the argparse.ArgumentParser
    Args:
        parser: argparse.ArgumentParser
    Returns:
        parser: a parser added with args
    """
    parser.add_argument(
        "-m",
        "--path_to_model_and_featurenames",
        type=str,
        default="./model.pickle",
        help="path to the pickled pre-trained model and the list of feature names.",
    )

    parser.add_argument(
        "-d",
        "--dir_to_save_outputs",
        type=str,
        default="./",
        help="path to directory where all outputs are saved.",
    )

    parser.add_argument(
        "-f",
        "--file_name",
        type=str,
        default="skX",
        help="name of the output binary.",
    )

    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default="lo",
        help="name of interface",
    )

    parser.add_argument("-s", "--stop_after_generation_of_sources", action="store_true")

    parser.add_argument("-c", "--stop_after_compile", action="store_true")

    parser.add_argument(
        "-t",
        "--tolerance",
        type=int,
        default=20,
        help="how many times skX should check the existence of the compiled object before attaching it to the network interface.",
    )

    return parser


def main():
    parser = add_args(
        argparse.ArgumentParser(
            description="SkimXDP: Elevate your network's defenses with the power of scikit-learn and XDP, the dynamic duo of packet filtering."
        )
    )
    args = parser.parse_args()

    c_content = template_program.replace(
        '#include "PLEASE_INCLUDE_APPRIPRIATE_HEADER_THAT_DEFINES_FILTER_MDOEL"',
        f'#include "{args.file_name}.h"',
    )
    with open(
        os.path.join(args.dir_to_save_outputs, args.file_name + ".c"), mode="w"
    ) as f:
        f.write(c_content)

    with open(
        os.path.join(args.dir_to_save_outputs, helper_header_name), mode="w"
    ) as f:
        f.write(helper_header)

    with open(args.path_to_model_and_featurenames, "rb") as f:
        clf, feature_names = pickle.load(f)
    header_content = export_clf_to_header(clf, feature_names)
    with open(
        os.path.join(args.dir_to_save_outputs, args.file_name + ".h"), mode="w"
    ) as f:
        f.write(header_content)

    if args.stop_after_generation_of_sources:
        return

    compile_clang_cmd = f"clang -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-compare -g -c -O2 -S -emit-llvm {os.path.join(args.dir_to_save_outputs, args.file_name + '.c')} -o - "
    p1 = subprocess.Popen(compile_clang_cmd.split(), stdout=subprocess.PIPE)
    compile_lcc_cmd = f"llc -march=bpf -filetype=obj -o {os.path.join(args.dir_to_save_outputs, args.file_name)}.o"
    p2 = subprocess.Popen(
        compile_lcc_cmd.split(), stdin=p1.stdout, stdout=subprocess.PIPE
    )
    p1.stdout.close()

    if args.stop_after_compile:
        return

    check_cnt = 0
    while not os.path.exists(
        os.path.join(args.dir_to_save_outputs, args.file_name + ".o")
    ):
        time.sleep(0.1)
        check_cnt += 1
        if check_cnt > args.tolerance:
            break

    attach_cmd = f"ip link set dev {args.interface} xdp obj {os.path.join(args.dir_to_save_outputs, args.file_name)}.o"
    subprocess.Popen(attach_cmd.split())
