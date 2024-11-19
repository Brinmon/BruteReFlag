import subprocess
import frida
import time
import itertools
import string

# 全局变量存储字节序列组合
byte_combinations = {}
combinations_len = 0

flaglen = 0x2a
flag = bytearray(b'!' * flaglen)
filename = "chall"
cmd = ['/home/kali/IDA_Debug/chall']
jscode = open("Hook.js", "rb").read().decode()


result = 0
def brute(F):

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

    except frida.NotSupportedError as e:
        print(f"Frida 错误: {e}")
        return None
    



def generate_byte_combinations(byte_size, charset):
    """生成指定字节数和字符集的所有组合,只生成一次"""
    global byte_combinations,combinations_len
    if (byte_size, charset) not in byte_combinations:
        byte_combinations[(byte_size, charset)] = list(itertools.product(charset, repeat=byte_size))
    if combinations_len == 0:
        combinations_len = len(byte_combinations[(byte_size, charset)])
        print(combinations_len)
    return byte_combinations[(byte_size, charset)]

def brute_force(byte_size, idx, charset='all'):
    """
    爆破函数

    :param byte_size: 每次返回的字节数
    :param idx: 控制爆破次数的索引
    :param charset: 字符集选择，默认为全体字符集
    :return: 字符组合
    """
    # 选择字符集
    if charset == 'all':
        charset = string.printable.strip()
    elif charset == 'uppercase':
        charset = string.ascii_uppercase
    elif charset == 'lowercase':
        charset = string.ascii_lowercase
    elif charset == 'digits':
        charset = string.digits
    elif charset == 'alphanumeric':
        charset = string.ascii_letters + string.digits
    else:
        raise ValueError("Invalid charset. Choose from 'all', 'uppercase', 'lowercase', 'digits', or 'alphanumeric'.")

    # 生成字节序列组合
    combinations = generate_byte_combinations(byte_size, charset)
    # print(len(combinations))
    # print(byte_combinations)
    # 检查索引是否有效
    if idx < 0 or idx >= len(combinations):
        raise IndexError("Index out of range")

    # 返回指定索引的字节组合
    return ''.join(combinations[idx])

# 设置特定位置字符过滤规则和强制赋值规则
def filter_flag(currentflag):
    # 强制赋值：如果第5个字符位置是空，就强制赋值为 'x'
    # 例如，强制第4个字符为特定值 'b'
    currentflag = list(currentflag)  # 转为列表才能修改指定位置
    if len(currentflag) >= 5:
        currentflag[4] = '{'  # 强制第4个字符为 'b'
        # currentflag[0] = 'f'  # 强制第4个字符为 'b'
        # currentflag[1] = 'l'  # 强制第4个字符为 'b'
        # currentflag[2] = 'a'  # 强制第4个字符为 'b'
        # currentflag[3] = 'g'  # 强制第4个字符为 'b'

    # 重新拼接回去
    currentflag = ''.join(currentflag)
    
    return currentflag  # 返回强制赋值后的结果
print("开始！")
CurrentTime = time.time()

flaglen = 44
bpvalue = "" #flag{Rea
flag = bpvalue +"!"*flaglen
count = len(bpvalue)
old_number = len(bpvalue)//2
init = brute_force(2,0,'all')
while count < flaglen:
    for i in range(combinations_len):
        currentcrackValue = brute_force(2,i,'all')
        currentflag = list(flag)
        currentcrackValue = list(currentcrackValue)
        currentflag[count] = currentcrackValue[0]
        currentflag[count+1] = currentcrackValue[1]
        Currentflag = ''.join(currentflag)
        # print(Currentflag)
        # 过滤规则
        # print("value",Currentflag)
        retvalue = filter_flag(Currentflag)
        if not retvalue:
            continue  # 如果不符合过滤条件，跳过当前组合        
        new_number = brute(retvalue.encode())
        print("value",retvalue)
        print("value",new_number)
        if old_number < new_number:
            print("old_number",old_number)
            print("new_number",new_number)
            old_number = new_number
            flag = ''.join(retvalue)
            Currentflag = flag
            count += 2
            print(f"本位耗时:{time.time()-CurrentTime}s,正确字符为：{flag}")
            break

