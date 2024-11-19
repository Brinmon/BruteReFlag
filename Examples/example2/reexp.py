import subprocess
import frida
import time
import itertools
import string
import json
from dataclasses import dataclass

@dataclass
class FlagStruct:
    currentbrutestr: str  # 当前爆破的字符
    flag_prefix : str  # flag前缀
    flaglen: int  # flag长度
    flagbasechunklen : int  # flag基本块长度
    flagbasechunkidx : int  # flag基本块长度
    realflag: str  # 真实flag

@dataclass
class StrCombinations:
    all_combinations : list  # 所有字节序列组合
    combinations_len : int  # 字节序列组合长度


def write_skipped_combinations_to_json(skipped_combinations, filename="skipped_combinations.json"):
    """
    将跳过的组合信息写入到 JSON 文件中

    :param skipped_combinations: 包含跳过的字符串和基本块索引的列表
    :param filename: 要保存的文件名
    """
    with open(filename, 'w') as json_file:
        json.dump(skipped_combinations, json_file, indent=4)
        print(f"跳过的组合信息已保存到 {filename}")

def Fridabrute(F):

    def on_message(message, data):
        global result
        if message['type'] == 'send':
            result = message['payload']
        else:
            print(message)

    # 启动进程
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               universal_newlines=True)

    # 获取子进程的 PID
    pid = process.pid
    print(f"子进程 PID: {pid}")  # 打印 PID，方便调试

    # 等待进程稳定
    time.sleep(0.001)  # 等待 2 秒，确保进程启动并稳定运行

    # 使用 PID 连接到进程
    try:
        session = frida.attach(pid)  
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()

        # 向子进程写入数据
        process.stdin.write(F.decode())
        print("value:",F.decode())
        time.sleep(0.001)  # 在这里添加等等是关键点
        # 处理子进程输出
        output, error = process.communicate()
        process.terminate()
        return result

    except frida.TimedOutError as e:
        print(f"Frida 错误: {e}")
        process.terminate()  # 杀死子进程
        return None
    except frida.NotSupportedError as e:
        print(f"Frida 错误: {e}")
        process.terminate()  # 杀死子进程
        return None
    except Exception as e:
        print(f"其他错误: {e}")
        process.terminate()  # 杀死子进程
        return None
    
def initbrute_table(byte_size):
    """
    爆破函数

    :param byte_size: 每次返回的字节数
    :return: 所有字符组合的列表
    """
    global CurrentStrCombinations
    # 选择字符集
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-{}' #abcdefghijklmnopqrstuvwxyz0123456789-{}
    
    # 生成指定字节数和字符集的所有组合
    combinations = list(itertools.product(charset, repeat=byte_size))
    print(combinations)
    CurrentStrCombinations.all_combinations = [''.join(combination) for combination in combinations]
    CurrentStrCombinations.combinations_len = len(combinations)

def initflag():
    """
    初始化flag
    :return: None
    """
    global Flag
    Flag.flag_prefix = "flag{R"
    Flag.flaglen = 44
    Flag.flagbasechunklen = 2
    Flag.flagbasechunkidx = 1
    Flag.currentbrutestr = Flag.flag_prefix + "!"*(Flag.flaglen-len(Flag.flag_prefix))
    Flag.realflag = ""

def filter_flag(currentflag):
    # 强制赋值：如果第5个字符位置是空，就强制赋值为 'x'
    # 例如，强制第4个字符为特定值 'b'
    currentflag = list(currentflag)  # 转为列表才能修改指定位置

    # 不允许的字符列表
    invalid_chars = ['a', 'b', 'c']

    # 检查第一个字符是否满足条件
    if currentflag[0] in invalid_chars:
        return False
    
    # 特殊检查，如果第一个字符是 '{' 或者 '}'，返回 False
    if currentflag[4] != '{' :
        return False
    
    return True  # 返回满足条件时

def UpdateFlagAtIndex(original_string, new_chars, index):
    """
    更新指定索引位置的字符串

    :param original_string: 原始字符串
    :param new_chars: 新字符字符串
    :param index: 更新的起始索引
    :return: 更新后的字符串
    """
    global Flag
    if index < 0 or index + len(new_chars) > len(original_string):
        raise IndexError("Index out of range for update.")

    # 将字符串转为列表以便修改
    string_list = list(original_string)
    
    # 更新指定索引位置的字符
    string_list[index:index + len(new_chars)] = new_chars
    if Flag.flagbasechunkidx*Flag.flagbasechunklen >=4:
        string_list[4] = '{'  # 强制第4个字符为 '{'
    Flag.currentbrutestr = ''.join(string_list)

def GetCurrentValueFlag(burteidx):
    """
    获取当前爆破的flag    
    :return: 当前爆破的flag
    """
    global Flag
    flag = list(Flag.currentbrutestr)
    Flag.flagbasechunklen = 2
    returnvalue = []
    for idx in range(Flag.flagbasechunklen):
        returnvalue.append(flag[burteidx*Flag.flagbasechunklen+idx])

    return ''.join(returnvalue) 

#爆破指定基本块的所有可能
def brute_force_allpossiblechunks(OldValueNum):
    """
    处理所有字符组合，更新flag并返回有效值表

    :param CurrentStrCombinations: 包含字符组合的对象
    :param OldValueNum: 之前的值用于比较
    :return: 有效值表列表
    """
    global CurrentStrCombinations,Flag
    CurrentTime = time.time()
    ValueNumTable = []
    skipped_combinations = []  # 用于存储跳过的组合信息
    for i in range(CurrentStrCombinations.combinations_len):
        UpdateFlagAtIndex(Flag.currentbrutestr, CurrentStrCombinations.all_combinations[i], OldValueNum*2)
        retvalue = filter_flag(Flag.currentbrutestr)
        
        if not retvalue:
            continue  # 如果不符合过滤条件，跳过当前组合
        
        print(Flag.currentbrutestr)
        ValueNum = Fridabrute(Flag.currentbrutestr.encode())
        if ValueNum == None:
            # 记录跳过的组合及其索引
            skipped_combinations.append({
                'skipped_string': Flag.currentbrutestr.encode(),
                'chunk_index': OldValueNum
            })
            continue  # 如果返回值为空，跳过当前组合

        if OldValueNum < ValueNum:
            print("当前有效块序号：", ValueNum)
            Flag.realflag = Flag.currentbrutestr
            ValueNum = OldValueNum
            ValueNumTable.append(GetCurrentValueFlag(OldValueNum))
            print(f"本位耗时:{time.time() - CurrentTime}s, 正确字符为：{Flag.realflag}")
    # write_skipped_combinations_to_json(skipped_combinations)
    return ValueNumTable


#初始化爆破字符表
global CurrentStrCombinations,Flag
CurrentStrCombinations = StrCombinations([],0)
Flag = FlagStruct("", "", 0, 0, 0, "")
initbrute_table(2)
initflag()
filename = "chall"
cmd = ['/home/kali/IDA_Debug/chall']
jscode = open("Hook.js", "rb").read().decode()

# 0idx ['dn', 'eo', 'fl', 'gm', 'hb', 'ic', 'ka', 'lf', 'mg', 'nd', 'oe', 'pz', 'q{', 'rx', 'sy', 'w}', 'xr', 'ys', 'zp', '28', '39', '82', '93']
# 1idx ['ag', 'bd', 'ce', 'db', 'ec', 'ga', 'hn', 'io', 'jl', 'km', 'lj', 'mk', 'nh', 'oi', 'pv', 'qw', 'rt', 'su', 'tr', 'us', 'vp', 'wq', '06', '17', '24', '35', '42', '53', '60', '71', '{}', '}{']
# 2idx ['{R']
print(brute_force_allpossiblechunks(3))
