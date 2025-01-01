import os
import threading


def open_and_hold_file(file_path, stop_event):
    """
    以只读方式打开文件并保持占用状态，直到接收到停止事件通知
    :param file_path: 文件的路径
    :param stop_event: 用于控制线程停止的事件对象
    """
    try:
        with open(file_path, 'r') as f:
            print(f"已打开并占用文件: {file_path}")
            # 持续保持文件打开占用状态，这里不再有根据停止事件结束的逻辑
            while True:
                pass
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")


# 指定的目录路径
directory = r'c:\1'

# 创建用于控制所有线程停止的事件对象，这里其实不再起作用了，但代码结构保留了
stop_event = threading.Event()

file_threads = []
# 遍历目录下的所有文件（可按需改成递归处理子目录情况）
for root, dirs, files in os.walk(directory):
    for file in files:
        file_path = os.path.join(root, file)
        # 为每个文件创建一个线程去打开并保持占用，传入停止事件对象
        t = threading.Thread(target=open_and_hold_file, args=(file_path, stop_event))
        t.start()
        file_threads.append(t)

print("所有文件已处于占用状态，程序将持续运行保持文件占用。")
# 主线程这里不再进行额外的等待等逻辑，让程序一直保持运行状态
while True:
    pass
    
