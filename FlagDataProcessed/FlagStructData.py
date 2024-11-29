from FlagDataProcessed import *

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
    def update_flag_prefix(self, new_prefix):
        """更新 flag 的前缀"""
        # 更新前缀
        self.Flagprefix = new_prefix
        # 重新构建 Currentbruteflag
        current_length = len(self.Currentbruteflag)
        suffix_length = len(self.Flagsuffix)

        # 新的 Currentbruteflag 将基于新前缀、现有长度和后缀进行重新组合
        self.Currentbruteflag = self.Flagprefix + '!' * (current_length - len(self.Flagprefix) - suffix_length) + self.Flagsuffix

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
