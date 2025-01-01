import sys
import joblib
import pefile
from collections import Counter
import math
import mmap
import numpy as np
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import os


# 加载训练好的模型
model_path = "virus_detection_model.pkl"
model = joblib.load(model_path)


def calculate_entropy(data):
    if not data:
        return 0
    # 使用 numpy 计算熵
    counter = Counter(data)
    probs = np.array(list(counter.values())) / len(data)
    entropy = -np.sum(probs * np.log2(probs))
    return entropy


def detect_encryption(file_data):
    # 简单的检测是否包含常见的加解密函数或字符串
    encryption_keywords = [b"encrypt"， b"decrypt"， b"crypto"， b"rsa"， b"aes"， b"des"]
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


def byte_distribution_task(mmapped_file, chunk_size):
    byte_distribution = np.zeros(256, dtype=np.int64)
    offset = 0
    while True:
        chunk = np.frombuffer(mmapped_file[offset:offset + chunk_size], dtype=np.uint8)
        if not chunk.size:
            break
        byte_distribution += np.bincount(chunk, minlength=256)
        offset += chunk_size
    return byte_distribution / offset


def entropy_task(mmapped_file, chunk_size):
    entropy = 0
    offset = 0
    total_length = len(mmapped_file)
    while True:
        chunk = mmapped_file[offset:offset + chunk_size]
        if not chunk:
            break
        entropy += calculate_entropy(chunk) * len(chunk) / total_length
        offset += chunk_size
    return entropy


def encryption_detected_task(mmapped_file):
    return detect_encryption(mmapped_file)


def pe_features_task(mmapped_file):
    try:
        return extract_pe_features(pefile.PE(data=mmapped_file))
    except Exception as e:
        print(f"无法提取 PE 特征: {e}")
        return None


@lru_cache(maxsize=128)
def extract_features(file_path):
    try:
        all_features = []
        chunk_size = 1024 * 1024  # 1MB 块大小
        with open(file_path, "rb") as f:
            # 使用 mmap 将文件映射到内存
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                num_workers = os.cpu_count()  # 根据 CPU 核心数确定线程池大小
                with ThreadPoolExecutor(max_workers=num_workers) as executor:
                    # 并行计算字节分布
                    byte_distribution_future = executor.submit(byte_distribution_task, mmapped_file, chunk_size)
                    # 并行计算熵
                    entropy_future = executor.submit(entropy_task, mmapped_file, chunk_size)
                    # 并行检测加密
                    encryption_detected_future = executor.submit(encryption_detected_task, mmapped_file)
                    # 并行提取 PE 特征
                    pe_features_future = executor.submit(pe_features_task, mmapped_file)

                    byte_distribution = byte_distribution_future.result()
                    entropy = entropy_future.result()
                    encryption_detected = encryption_detected_future.result()
                    pe_features = pe_features_future.result()

                    if pe_features is not None:
                        all_features.extend(pe_features)

                    all_features.extend([entropy, encryption_detected])
                    all_features.extend(byte_distribution.tolist())

                    # 提取文件的前 6000 位字节序列作为新特征
                    first_6000_bytes = np.frombuffer(mmapped_file[:6000], dtype=np.uint8)
                    if len(first_6000_bytes) < 6000:
                        first_6000_bytes = np.pad(first_6000_bytes, (0, 6000 - len(first_6000_bytes)), 'constant')
                    all_features.extend(first_6000_bytes.tolist())

                    # 确保特征数量与训练模型时使用的特征数量相同
                    target_length = 6285
                    if len(all_features) > target_length:
                        all_features = all_features[:target_length]
                    elif len(all_features) < target_length:
                        all_features += [0] * (target_length - len(all_features))

                    return all_features

    except FileNotFoundError:
        print(f"文件 {file_path} 不存在")
        return None
    except PermissionError:
        print(f"没有权限访问文件 {file_path}")
        return None
    except Exception as e:
        print(f"无法读取文件 {file_path}: {e}")
        # 尝试提取其他特征
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
                entropy = calculate_entropy(file_data)
                encryption_detected = detect_encryption(file_data)
                all_features = [entropy, encryption_detected]
                # 提取文件的前 6000 位字节序列作为新特征
                first_6000_bytes = list(file_data[:6000]) if len(file_data) >= 6000 else list(file_data) + [0] * (6000 - len(file_data))
                all_features.extend(first_6000_bytes)
                # 确保特征数量与训练模型时使用的特征数量相同
                target_length = 6285
                if len(all_features) > target_length:
                    all_features = all_features[:target_length]
                elif len(all_features) < target_length:
                    all_features += [0] * (target_length - len(all_features))
                return all_features
        except Exception as e:
            print(f"这个文件很逆天: {e}")
            return None


def predict_virus(file_path):
    features = extract_features(file_path)
    if features is None:
        sys.exit(0)  # 文件处理出现异常，退出代码为 0

    # 使用训练好的模型进行预测
    prediction = model.predict([features])

    if prediction[0] == 1:
        sys.exit(1)  # 预测为病毒文件，退出代码为 1
    else:
        sys.exit(0)  # 预测为良性文件，退出代码为 0


if __name__ == "__main__":
    if len(sys.argv)!= 2:
        print("请输入正确的文件路径作为命令行参数--卡哇伊")
        sys.exit(0)
    file_path = sys.argv[1]
    predict_virus(file_path)
