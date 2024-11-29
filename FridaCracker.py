# 导入FlagDataProcessed包中的所有函数和方法
from FlagDataProcessed.FlagStructData import *
from FlagDataProcessed.GenerBruteData import *

# 导入FridaCracker包中的所有函数和方法
from FridaCracker.FridaCrackerBase import *


cmd = ['/home/kali/GithubProject/BruteReFlag/Examples/example2/chall']
jscode = open("/home/kali/GithubProject/BruteReFlag/Examples/example2/Hook.js", "rb").read().decode()

BaseChunkNum = 1   #flag的基本块长度
globalmust_idx_value_pairs = [] # 需要绕过的flag字符的索引和值
globalcannot_idx_value_pairs = [] # 
FridaCracker = FridaCrackerBase(cmd, jscode)
FinalFlag = FlagStruct(full_flag="", 
                       flag_prefix="flag{ReAl1y_ez_cPp_vMach1n4_d0_YoU_L1k4_lT?^_^",
                       flag_suffix="",
                       flag_len=47,
                       flag_base_chunk_len=BaseChunkNum)

# 定义字符集
charset = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[]^_`{|}~ """  #少了\
length = BaseChunkNum  # 每个组合的长度
# 创建 BruteDataCombinations 实例
brute_data_combinations = BruteDataCombinations(charset, length)
# 将字符集和组合写入到文件
brute_data_combinations.write_charset_to_file()


start_time = time.time()
for idx in range(len(FinalFlag.Flagprefix), FinalFlag.Flaglen):
    CurrentBaseChunkAllPosTable = FridaBruteOneChunkValue(FridaCracker, FinalFlag, idx)
    if CurrentBaseChunkAllPosTable is None:
        raise ValueError("本次爆破失败,无任何值匹配!!!")
    FinalFlag.update_flag_prefix(FinalFlag.Flagprefix+CurrentBaseChunkAllPosTable)
    print(f"当前Flag前缀为: {FinalFlag.Flagprefix}")
# 记录结束时间
end_time = time.time()

# 计算运行时间
elapsed_time = end_time - start_time
print(f"运行时间: {elapsed_time:.4f}秒")  # 格式化输出，最多保留4位小数


