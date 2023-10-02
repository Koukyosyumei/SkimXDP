import math

from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.ensemble import RandomForestClassifier

# include_def = "#include <stdint.h>\n"
# func_def = (
#    "inline int filter_func(unsigned int ip_ihl, unsigned int ip_version,\n"
#    "                        int ip_preference, int ip_dscp, uint16_t ip_total_length,\n"
#    "                        uint16_t ip_frag_offset, uint8_t ip_ttl, uint8_t ip_protocol,\n"
#    "                        uint16_t tcp_source_port, uint16_t tcp_dest_port,\n"
#    "                        unsigned int tcp_sequence_num, unsigned int tcp_ack_num,\n"
#    "                        uint16_t tcp_window_size, uint16_t tcp_urgent_pointer, uint16_t tcp_cwr_flag,\n"
#    "                        uint16_t tcp_ece_flag, uint16_t tcp_urg_flag, uint16_t tcp_ack_flag,\n"
#    "                        uint16_t tcp_psh_flag, uint16_t tcp_rst_flag, uint16_t tcp_syn_flag, uint16_t tcp_fin_flag) {\n"
# )

endl = "\n"
par_left = "{"
par_right = "}"


def dump_tree(clf, feature_names, node_idx=0, indent_cnt=4, indent_char=" "):
    code = ""
    if clf.tree_.threshold[node_idx] != -2:
        code += f"{indent_cnt*indent_char}if ({feature_names[clf.tree_.feature[node_idx]]} <= {int(clf.tree_.threshold[node_idx])}) {par_left+endl}"
        indent_cnt += 1

        if clf.tree_.children_left[node_idx] != -1:
            code += dump_tree(
                clf,
                feature_names,
                clf.tree_.children_left[node_idx],
                indent_cnt,
                indent_char,
            )
        indent_cnt -= 1
        code += f"{indent_cnt*indent_char+par_right+endl+indent_cnt*indent_char}else {par_left+endl}"

        indent_cnt += 1
        if clf.tree_.children_right[node_idx] != -1:
            code += dump_tree(
                clf,
                feature_names,
                clf.tree_.children_right[node_idx],
                indent_cnt,
                indent_char,
            )
        indent_cnt -= 1
        code += indent_cnt * indent_char + par_right + endl

    else:
        code += (
            f"{indent_cnt*indent_char}y += {clf.tree_.value[node_idx].argmax()};{endl}"
        )

    return code


def dump_randomforest(clf, feature_names, node_idx=0, indent_cnt=4, indent_char=" "):
    code = ""
    for estimator in clf.estimators_:
        code += dump_tree(estimator, feature_names, node_idx, indent_cnt, indent_char)
    code += f"{endl}{indent_cnt * indent_char}y = (y > {math.floor(len(clf.estimators_) / 2)});{endl}"
    return code


def dump_linear_model(clf, feature_names, threshold=0, precision=4, indent_char=" "):
    code = indent_char
    code += f"y += ({int(clf.intercept_[0] * (10**(precision)))}"
    for c, n in zip(clf.coef_[0], feature_names):
        code += f" + ({int(c * (10**precision))} * {n})"
    code += f") > {int(threshold * (10 ** precision))};{endl}"
    return code


def export_clf(clf, feature_names, threshold=0, precision=4):
    if type(clf) == DecisionTreeClassifier:
        dumped_clf = dump_tree(clf, feature_names, indent_char=" ")
    elif type(clf) == RandomForestClassifier:
        dumped_clf = dump_randomforest(clf, feature_names, indent_char=" ")
    elif type(clf) in [LogisticRegression, RidgeClassifier]:
        dumped_clf = dump_linear_model(
            clf,
            feature_names,
            threshold=threshold,
            indent_char=" " * 4,
            precision=precision,
        )
    else:
        raise ValueError(f"{type(clf)} is not supported.")

    return dumped_clf
