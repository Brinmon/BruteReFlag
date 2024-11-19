from  FridaCrackerModel import *

# 定义FlagStruct类，用于存储爆破过程中的信息
class FlagStruct:  
    def __init__(self, full_flag="", flag_prefix="", flag_suffix="", flag_len=0, flag_base_chunk_len=0):  
        self.Fullfalg = full_flag  # 完整flag
        self.Flagprefix = flag_prefix  # flag前缀
        self.Flagsuffix = flag_suffix  # flag后缀
        self.Flaglen = flag_len  # flag长度
        self.Flagbasechunklen = flag_base_chunk_len  # flag基本块长度
        if flag_prefix == "" and flag_suffix == "":  
            self.Currentbruteflag = '!'*flag_len  # 如果没有前缀和后缀就直接使用'!'*flag_len
        else:  
            self.Currentbruteflag = flag_prefix + '!'*(flag_len-len(flag_prefix)-len(flag_suffix)) + flag_suffix  # 如果有就直接开始拼接

    def save_flag_to_file(self, filename='flag_data.json'):
        """将当前的flag存储到文件中"""
        # 构造上级目录的路径
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', filename)
        flag_data = {
            'Fullfalg': self.Fullfalg,
            'Flagprefix': self.Flagprefix,
            'Flagsuffix': self.Flagsuffix,
            'Flaglen': self.Flaglen,
            'Flagbasechunklen': self.Flagbasechunklen,
            'Currentbruteflag': self.Currentbruteflag,
        }
        with open(file_path, 'w') as f:
            json.dump(flag_data, f, indent=4)
        print(f"Flag data has been saved to {file_path}")

    @classmethod
    def load_flag_from_file(cls, filename='flag_data.json'):
        """从文件中加载flag"""
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', filename)
        with open(file_path, 'r') as f:
            flag_data = json.load(f)
        # 使用加载的数据恢复类的实例
        return cls(
            full_flag=flag_data['Fullfalg'],
            flag_prefix=flag_data['Flagprefix'],
            flag_suffix=flag_data['Flagsuffix'],
            flag_len=flag_data['Flaglen'],
            flag_base_chunk_len=flag_data['Flagbasechunklen'],
            current_brute_flag=flag_data['Currentbruteflag']
        )

    def update_current_brute_flag(self, updateidx, updatenum, updatechars):
        """更新当前的brute flag"""
        # 确保 updateidx 和 updatenum 在有效范围内
        if updateidx < 0 or updateidx >= self.Flaglen:
            raise IndexError("updateidx 超出范围")

        if updatenum <= 0 or (updateidx + updatenum) > self.Flaglen:
            raise ValueError("updatenum 超出范围或为无效值")

        # 将当前的brute flag 转为列表以更改特定字符
        current_flag_list = list(self.Currentbruteflag)

        # 检查updatechars的长度是否与updatenum匹配
        if len(updatechars) != updatenum:
            raise ValueError("updatechars 的长度与 updatenum 不匹配")

        # 更新指定的部分
        for i in range(updatenum):
            current_flag_list[updateidx + i] = updatechars[i]

        # 将列表重新转换为字符串并更新Currentbruteflag
        self.Currentbruteflag = ''.join(current_flag_list)

    def filter_flag(self, must_idx_value_pairs, cannot_idx_value_pairs):
        """
        根据给定的过滤条件过滤当前的brute flag  
        如果不满足条件就返回false, 否则返回true

        :param must_idx_value_pairs: 必须满足的条件列表，每个元素为(idx, value)形式
        :param cannot_idx_value_pairs: 必须不满足的条件列表，每个元素为(idx, value)形式
        :return: bool
        """
        # 验证必须满足的条件
        for idx, value in must_idx_value_pairs:
            if idx < 0 or idx >= self.Flaglen:
                raise IndexError(f"Index {idx} 超出范围")
            if self.Currentbruteflag[idx] != value:
                return False  # 一旦有不满足条件的，返回 False

        # 验证必须不满足的条件
        for idx, value in cannot_idx_value_pairs:
            if idx < 0 or idx >= self.Flaglen:
                raise IndexError(f"Index {idx} 超出范围")
            if self.Currentbruteflag[idx] == value:
                return False  # 一旦有不满足条件的，返回 False

        return True  # 所有条件都满足，返回 True


class BruteDataCombinations:
    def __init__(self, charset, length):
        """
        初始化 BruteDataCombinations 类

        :param charset: 字符集表
        :param length: 生成组合的长度

        常见的的字符表集合，如：
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"  
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  
        "0123456789abcdefABCDEF"  
        "0123456789"  
        "abcdefghijklmnopqrstuvwxyz"  
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
        "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-{}[]|\\:;\"'<>,.?/~`"  
        "{}[]()<>,.?/~_+-=|\\:;\"'!"

        """
        self.Charset = charset  # 字符集
        self.AllCombinations = [''.join(combination) for combination in itertools.product(charset, repeat=length)]
        
        # 设置默认输出目录为上一级目录的 Data 文件夹
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Data')
        os.makedirs(self.output_dir, exist_ok=True)  # 确保输出目录存在

    def write_charset_to_file(self, filename='charset.json'):
        """
        将字符集以JSON格式写入文件，方便其他程序读取

        :param filename: 要保存的文件名
        """
        file_path = os.path.join(self.output_dir, filename)
        charset_data = {
            'charset': self.Charset,
            'combinations': self.AllCombinations
        }
        with open(file_path, 'w') as f:
            json.dump(charset_data, f, indent=4, ensure_ascii=False)
        print(f"字符集已以JSON格式写入到文件: {file_path}")

    def split_charset_to_files(self, num_files=5):
        """
        将生成的字符串组合拆分成多份文件，供其他进程读取爆破

        :param num_files: 拆分文件的数量
        """
        combinations_per_file = len(self.AllCombinations) // num_files
        for i in range(num_files):
            start_index = i * combinations_per_file
            end_index = (i + 1) * combinations_per_file if i < num_files - 1 else len(self.AllCombinations)
            chunk = self.AllCombinations[start_index:end_index]
            filename = f'combinations_part_{i + 1}.json'
            file_path = os.path.join(self.output_dir, filename)
            with open(file_path, 'w') as f:
                json.dump({'combinations': chunk}, f, indent=4, ensure_ascii=False)
            print(f"字符串组合的第{i + 1}部分已写入到文件: {file_path}")


#需要一个专门读取json文件的函数读取BurteDataCombinations类生成的字符集表和组合
def read_charset_from_file(filename='charset.json'):
    """
    从文件中读取字符集表和组合

    :param filename: 要读取的文件名
    :return: 字符集表和组合
    """
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Data', filename)
    with open(file_path, 'r') as f:
        charset_data = json.load(f)
    return charset_data['combinations']


# 全局调试标志
debug_mode = True
info_mode = True

# 设置输出模式
def set_print_mode(info_enabled, debug_enabled):
    """设置输出模式"""
    global info_mode, debug_mode
    info_mode = info_enabled
    debug_mode = debug_enabled
   
def DBG(message):
    """输出调试信息 (蓝色)"""
    if debug_mode:
        print(f"\033[94mDEBUG: {message}\033[0m")  # ANSI 转义序列，\033[94m 是蓝色，\033[0m 重置为默认颜色

def ERR(message):
    """输出错误信息 (红色)"""
    print(f"\033[91mERROR: {message}\033[0m")  # ANSI 转义序列，\033[91m 是红色，\033[0m 重置为默认颜色

def INFO(message):
    """输出信息 (绿色)"""
    if info_mode:
        print(f"\033[92mINFO: {message}\033[0m")  # ANSI 转义序列，\033[92m 是绿色，\033[0m 重置为默认颜色


