from FlagDataProcessed import *

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
        0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ 
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
