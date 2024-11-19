from FridaCrackerModel import *

cmd = ['/home/kali/GithubProject/BruteReFlag/examples/example2/chall']
jscode = open("/home/kali/GithubProject/BruteReFlag/examples/example2/Hook.js", "rb").read().decode()
FridaCracker = FridaCrackerBase(cmd, jscode)

FinalFlag = FlagStruct(full_flag="", 
                       flag_prefix="flag{R",
                       flag_suffix="}",
                       flag_len=44,
                       flag_base_chunk_len=1)
globalmust_idx_value_pairs = []
globalcannot_idx_value_pairs = []

charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-{}'  # 定义字符集
length = 1  # 每个组合的长度
# 创建 BruteDataCombinations 实例
brute_data_combinations = BruteDataCombinations(charset, length)
# 将字符集和组合写入到文件
brute_data_combinations.write_charset_to_file()
# idx4,5 CurrentBaseChunkAllPosTable:  ['Ah', 'Bk', 'Cj', 'Dm', 'El', 'Fo', 'Gn', 'Ha', 'Jc', 'Kb', 'Le', 'Md', 'Ng', 'Of', 'Py', 'Qx', 'R{', 'Sz', 'T}', 'Xq', 'Yp', 'Zs', 'aH', 'bK', 'cJ', 'dM', 'eL', 'fO', 'gN', 'hA', 'jC', 'kB', 'lE', 'mD', 'nG', 'oF', 'pY', 'qX', 'sZ', 'xQ', 'yP', 'zS', '{R', '}T'] 运行时间: 211.7694秒
start_time = time.time()
CurrentBaseChunkAllPosTable = FridaBruteAllPossibleChunksForOne(FridaCracker, FinalFlag, 6)
# 记录结束时间
end_time = time.time()

# 计算运行时间
elapsed_time = end_time - start_time
print("CurrentBaseChunkAllPosTable: ", CurrentBaseChunkAllPosTable)
print(f"运行时间: {elapsed_time:.4f}秒")  # 格式化输出，最多保留4位小数


