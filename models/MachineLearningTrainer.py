import os
import time
import numpy as np
import math
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import pefile


def calculate_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy


def detect_encryption(file_data):
    # 简单的检测是否包含常见的加解密函数或字符串
    encryption_keywords = [b"encrypt", b"decrypt", b"crypto", b"rsa", b"aes", b"des"]
    for keyword in encryption_keywords:
        if keyword in file_data:
            return 1
    return 0


def extract_pe_features(pe):
    try:
        # 提取一些 PE 文件的结构字段
        dos_header = pe.DOS_HEADER
        file_header = pe.FILE_HEADER
        optional_header = pe.OPTIONAL_HEADER

        features = [
            dos_header.e_magic,  # DOS 头魔术数字
            dos_header.e_lfanew,  # PE 头偏移量
            file_header.Machine,  # 机器类型
            file_header.NumberOfSections,  # 节数量
            optional_header.AddressOfEntryPoint,  # 入口点地址
            optional_header.ImageBase,  # 映像基地址
            optional_header.SectionAlignment,  # 节对齐
            optional_header.FileAlignment,  # 文件对齐
            optional_header.SizeOfImage,  # 映像大小
            optional_header.SizeOfHeaders,  # 头大小
            optional_header.CheckSum,  # 校验和
            optional_header.Subsystem,  # 子系统
            optional_header.SizeOfStackReserve,  # 堆保留大小
            optional_header.SizeOfStackCommit,  # 堆提交大小
            optional_header.SizeOfHeapReserve,  # 堆保留大小
            optional_header.SizeOfHeapCommit,  # 堆提交大小
            optional_header.NumberOfRvaAndSizes  # RVA 和大小数量
        ]
        return features
    except Exception as e:
        print(f"无法提取 PE 特征: {e}")
        return None


def extract_features(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()

        byte_distribution = [0] * 256
        for byte in file_data:
            byte_distribution[byte] += 1
        byte_distribution = [x / len(file_data) for x in byte_distribution]  

        entropy = calculate_entropy(file_data)

        first_bytes = list(file_data[:10]) if len(file_data) >= 10 else [0] * 10

        encryption_detected = detect_encryption(file_data)

        pe_features = []
        try:
            pe = pefile.PE(file_path)
            pe_features = extract_pe_features(pe)
        except pefile.PEFormatError:
            print(f"文件 {file_path} 不是有效的 PE 文件")
            return None

        # 提取文件的前 6000 位字节序列作为新特征
        first_6000_bytes = list(file_data[:6000]) if len(file_data) >= 6000 else list(file_data) + [0] * (6000 - len(file_data))

        return [entropy, encryption_detected] + pe_features + byte_distribution + first_bytes + first_6000_bytes

    except Exception as e:
        print(f"无法读取文件 {file_path}: {e}")
        return None


def process_file(file_path, label):
    """
    处理单个文件并提取特征，同时返回标签。
    """
    feature = extract_features(file_path)
    if feature is not None:
        return feature, label
    return None, None


def create_dataset(virus_dir, benign_dir):
    """
    创建数据集：
    遍历病毒样本和良性样本文件夹，调用特征提取函数提取特征并生成标签。
    """
    features = []
    labels = []

    print("正在提取样本特征...")

    # 准备所有文件路径和对应标签
    files_and_labels = []

    for file_name in os.listdir(virus_dir):
        file_path = os.path.join(virus_dir, file_name)
        files_and_labels.append((file_path, 1))  # 标签为 1，表示病毒文件

    for file_name in os.listdir(benign_dir):
        file_path = os.path.join(benign_dir, file_name)
        files_and_labels.append((file_path, 0))  # 标签为 0，表示良性文件

    for file_path, label in files_and_labels:
        feature, label = process_file(file_path, label)
        if feature is not None:
            features.append(feature)
            labels.append(label)

    return np.array(features), np.array(labels)


def train_model(features, labels):
    global y_test, y_pred
    X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("模型性能报告：")
    print(classification_report(y_test, y_pred))
    accuracy = accuracy_score(y_test, y_pred)
    print("准确率：", accuracy)

    return model, accuracy


def save_model(model, output_path):
    """
    导出模型到文件。
    """
    joblib.dump(model, output_path)
    print(f"模型已保存到 {output_path}")


if __name__ == "__main__":
    virus_samples_dir = "C:/3"  
    benign_samples_dir = "C:/4"  

    start_time = time.time()

    print("正在创建数据集...")
    features, labels = create_dataset(virus_samples_dir, benign_samples_dir)

    if features.size == 0 or labels.size == 0:
        print("数据集为空，请检查样本路径或样本内容。")
    else:
        print("正在训练模型...")
        model, accuracy = train_model(features, labels)

        model_path = "virus_detection_model.pkl"
        save_model(model, model_path)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"程序运行完毕，总耗时：{elapsed_time:.2f} 秒")
        print(f"最终模型准确率：{accuracy:.2f}")

        # 将结果保存到文件
        with open("virus_detection_results.txt", "w", encoding="utf-8") as f:
            f.write(f"程序运行完毕，总耗时：{elapsed_time:.2f} 秒\n")
            f.write(f"最终模型准确率：{accuracy:.2f}\n")
            f.write("模型性能报告：\n")
            f.write(classification_report(y_test, y_pred))
