from  FridaCrackerModel import *

globalmust_idx_value_pairs = []
globalcannot_idx_value_pairs = []

#定义一个FridaCrackerBase类
class FridaCrackerBase(object):
    def __init__(self, cmd, jscode):
        self.cmd = cmd
        self.jscode = jscode

    def FridaBrute(self,F):
        def on_message(message, data):
            INFO(message)
            nonlocal result  # 声明 result 为 nonlocal，以便访问外部作用域的变量
            if message['type'] == 'send':
                result = message['payload']
            else:
                print(message)
        result = None  # 初始化 result 变量
        # 启动进程
        process = subprocess.Popen(self.cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True)

        time.sleep(0.001)  # slepp一会，确保进程启动并稳定运行

        # 使用 PID 连接到进程
        try:
            session = frida.attach(process.pid)  
            script = session.create_script(self.jscode)
            script.on('message', on_message)
            script.load()
            # 向子进程写入数据
            process.stdin.write(F.decode())
            time.sleep(0.001)  # 添加sleep确保数据写入
            # 处理子进程输出
            output, error = process.communicate()
                # 检测 output 中的指定字符串
            success_indicator = "right"  # 替换为你需要检测的字符串
            if success_indicator in output:
                INFO(f"Flag 爆破成功!,正确的flag是:{F.decode()}")
                sys.exit(0)  # 退出程序，并返回状态码 0（成功）
            process.terminate()
            INFO(f"子进程输出: {output,result}")
            return result

        except Exception as e:
            ERR(f"其他错误: {e}")
            process.terminate()  # 杀死子进程
            return None
        

#爆破指定序号的基本块的所有可能
def FridaBruteAllPossibleChunksForOne(CurrentFridaCrackerBaseBase:FridaCrackerBase,CurrentFlagStruct:FlagStruct,KnownBaseChunkIdx:int):
    """
    KnownBaseChunkIdx: 指定的flag字节的序号
    """
    CurrentTime = time.time()
    CurrentBaseChunkAllPosTable = []
    ErrorInfo = []  # 用于存储跳过的组合信息
    AllBruteStrCombinations = read_charset_from_file("charset.json")
    StartBaseChunkIdx = CurrentFridaCrackerBaseBase.FridaBrute(CurrentFlagStruct.Currentbruteflag.encode())
    for i in range(len(AllBruteStrCombinations)):
        CurrentBruteStr = AllBruteStrCombinations[i]
        
        CurrentFlagStruct.update_current_brute_flag(KnownBaseChunkIdx,CurrentFlagStruct.Flagbasechunklen,CurrentBruteStr)
        IsBrute = CurrentFlagStruct.filter_flag(globalmust_idx_value_pairs, globalcannot_idx_value_pairs)
        if not IsBrute:
            continue  # 如果不符合过滤条件，跳过当前组合

        GetNewBaseChunkIdx = CurrentFridaCrackerBaseBase.FridaBrute(CurrentFlagStruct.Currentbruteflag.encode())
        INFO(f"当前投喂的flag是:{CurrentFlagStruct.Currentbruteflag}")
        if GetNewBaseChunkIdx == None:
            ErrorInfo.append(CurrentBruteStr)
            continue  # 如果返回值为空，跳过当前组合
        if GetNewBaseChunkIdx > StartBaseChunkIdx:
            CurrentBaseChunkAllPosTable.append(CurrentBruteStr)
            INFO(f"本位耗时:{time.time() - CurrentTime}s, 正确字符为：{CurrentFlagStruct.Currentbruteflag}")
    # 遍历和处理逻辑结束后
    if ErrorInfo:
        error_info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Data', 'error_info.json')
        os.makedirs(os.path.dirname(error_info_path), exist_ok=True)  # 确保目录存在
        with open(error_info_path, 'w') as f:
            json.dump(ErrorInfo, f, indent=4, ensure_ascii=False)
        INFO(f"错误信息已保存到文件: {error_info_path}")
    else:
        INFO("没有错误信息，未写入文件。")

    return CurrentBaseChunkAllPosTable

#爆破指定序号的基本块的最可能的一个值
def FridaBruteOneChunkValue(CurrentFridaCrackerBaseBase:FridaCrackerBase,CurrentFlagStruct:FlagStruct,KnownBaseChunkIdx:int):
    """
    KnownBaseChunkIdx: 指定的flag字节的序号
    """
    CurrentTime = time.time()
    CurrentBaseChunkAllPosTable = []
    ErrorInfo = []  # 用于存储跳过的组合信息
    AllBruteStrCombinations = read_charset_from_file("charset.json")
    StartBaseChunkIdx = CurrentFridaCrackerBaseBase.FridaBrute(CurrentFlagStruct.Currentbruteflag.encode())
    for i in range(len(AllBruteStrCombinations)):
        CurrentBruteStr = AllBruteStrCombinations[i]                
        CurrentFlagStruct.update_current_brute_flag(KnownBaseChunkIdx,CurrentFlagStruct.Flagbasechunklen,CurrentBruteStr)
        IsBrute = CurrentFlagStruct.filter_flag(globalmust_idx_value_pairs, globalcannot_idx_value_pairs)
        if not IsBrute:
            continue  # 如果不符合过滤条件，跳过当前组合
        GetNewBaseChunkIdx = CurrentFridaCrackerBaseBase.FridaBrute(CurrentFlagStruct.Currentbruteflag.encode())
        INFO(f"当前投喂的flag是:{CurrentFlagStruct.Currentbruteflag}")
        if GetNewBaseChunkIdx == None:            
            ErrorInfo.append(CurrentBruteStr)            
            continue  # 如果返回值为空，跳过当前组合                            
        if GetNewBaseChunkIdx > StartBaseChunkIdx:          
            CurrentBaseChunkAllPosTable.append(CurrentBruteStr)
            INFO(f"本位耗时:{time.time() - CurrentTime}s, 正确字符为：{CurrentFlagStruct.Currentbruteflag}")
            # 遍历和处理逻辑结束后
            if ErrorInfo:
                error_info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Data', 'error_info.json')
                os.makedirs(os.path.dirname(error_info_path), exist_ok=True)  # 确保目录存在
                with open(error_info_path, 'w') as f:
                    json.dump(ErrorInfo, f, indent=4, ensure_ascii=False)
                INFO(f"错误信息已保存到文件: {error_info_path}")
            else:
                INFO("没有错误信息，未写入文件。")
            return CurrentBaseChunkAllPosTable[0]
    return None
