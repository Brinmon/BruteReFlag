# examples例题特征
nor.nor : 题目进行单字节验证,错误一个字符直接退出,但是无法找到flag校验的位置,目前只能采用侧信道攻击


# PinCracker pintools侧信道攻击脚本
## 环境要求
pintool不同版本的下载地址:https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html
目前使用版本:https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz
将压缩包下载下来之后直接解压到目标目录再添加环境变量就可以了!
```bash
# 添加Pin工具到PATH
export PIN_ROOT=~/tools/pintool
export PATH=$PIN_ROOT:$PATH
```
## inscountInaddr0 : 
```d
┌──(kali㉿kali)-[~/GithubProject/pintool-RE/inscountInaddr0]
└─$ ls
instracebyaddrlog0.cpp  makefile  makefile.rules
```

makefile.rules:这个文件目前就instracebyaddrlog0有用,用来给编译出来的so文件命名!
```d
...
# 这定义了运行同名工具的测试。这只是为了方便避免两次定义测试名称（一次在TOOL_ROOTS中，另一次在TEST_ROOTS中）。
# 这里定义的测试不应在TOOL_ROOTS和TEST_ROOTS中定义。
TEST_TOOL_ROOTS := instracebyaddrlog0
...
```

makefile:这文件需要配置一下pintool的路径,我添加了`$(PIN_ROOT)`所以如果设置了环境变量就不需要修改!
```d
...
# If the tool is built out of the kit, PIN_ROOT must be specified in the make invocation and point to the kit root.
PIN_ROOT :=$(if $(PIN_ROOT),$(PIN_ROOT),/home/kali/tools/pintools/pin-3.30-gcc-linux)
ifdef PIN_ROOT
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
else
CONFIG_ROOT := ../Config
endif
include $(CONFIG_ROOT)/makefile.config
include makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules
...

```

instracebyaddrlog0.cpp:就是我编写的动态劫持库了
```c++
KNOB< ADDRINT > KnobTargetAddressOffest(KNOB_MODE_WRITEONCE, "pintool", "addroffest", "0", "指定目标插桩位置的偏移");

// ImageLoad回调函数
VOID ImageLoad(IMG img, VOID* v)  //获取elf的基地址解决无法hook开启了pie的程序
{}
// 每次遇到新指令时，Pin调用这个函数
VOID Instruction(INS ins, VOID* v)//对每个指令进行插桩
{}


int main(int argc, char* argv[])
{
    // 初始化Pin
    if (PIN_Init(argc, argv)) return Usage();

    // 注册ImageLoad回调函数
    IMG_AddInstrumentFunction(ImageLoad, NULL);

    // 注册Instruction函数以便插装指令
    INS_AddInstrumentFunction(Instruction, 0);

    // 注册Fini函数以便在应用程序退出时调用
    PIN_AddFiniFunction(Fini, 0);

    // 启动程序，永不返回
    PIN_StartProgram();

    return 0;
}

```

再环境装配完成之后就可以开始编译了!
```d
#编译32位
└─$  make obj-ia32/instracebyaddrlog0.so TARGET=ia32
或者 make all TARGET=ia32
#编译64位
└─$ make obj-intel64/instracebyaddrlog0.so TARGET=intel64 
或者 make all TARGET=intel64 
```


// 注册Instruction函数以便插装指令
INS_AddInstrumentFunction(Instruction, 0);
通过对每条汇编指令插入回调函数来实现程序插桩，INS_InsertCall



# FridaCracker frida侧信道攻击脚本
## 测试案例:前部分双字节加密后面的部分单字节加密

### 爆破出第一部分的可能性

```python
from FridaCrackerModel import *

cmd = ['/home/kali/GithubProject/BruteReFlag/examples/example2/chall']
jscode = open("/home/kali/GithubProject/BruteReFlag/examples/example2/Hook.js", "rb").read().decode()
FridaCracker = FridaCrackerBase(cmd, jscode)

FinalFlag = FlagStruct(full_flag="", 
                       flag_prefix="",
                       flag_suffix="}",
                       flag_len=44,
                       flag_base_chunk_len=2)

# 记录flag:idx0,1 CurrentBaseChunkAllPosTable:  ['ak', 'bh', 'ci', 'dn', 'eo', 'fl', 'gm', 'hb', 'ic', 'ka', 'lf', 'mg', 'nd', 'oe', 'pz', 'q{', 'rx', 'sy', 'w}', 'xr', 'ys', 'zp', '28', '39', '82', '93', '{q', '}w']

start_time = time.time()
CurrentBaseChunkAllPosTable = FridaBruteAllPossibleChunksForOne(FridaCracker, FinalFlag, 0)
# 记录结束时间
end_time = time.time()

# 计算运行时间
elapsed_time = end_time - start_time
print("CurrentBaseChunkAllPosTable: ", CurrentBaseChunkAllPosTable)
print(f"运行时间: {elapsed_time:.4f}秒")  # 格式化输出，最多保留4位小数
```

### 爆破出第二部分的可能性

```python
from FridaCrackerModel import *

cmd = ['/home/kali/GithubProject/BruteReFlag/examples/example2/chall']
jscode = open("/home/kali/GithubProject/BruteReFlag/examples/example2/Hook.js", "rb").read().decode()
FridaCracker = FridaCrackerBase(cmd, jscode)

FinalFlag = FlagStruct(full_flag="", 
                       flag_prefix="fl",
                       flag_suffix="}",
                       flag_len=44,
                       flag_base_chunk_len=2)

# 记录flag:idx2,3 CurrentBaseChunkAllPosTable:  ['ag', 'bd', 'ce', 'db', 'ec', 'ga', 'hn', 'io', 'jl', 'km', 'lj', 'mk', 'nh', 'oi', 'pv', 'qw', 'rt', 'su', 'tr', 'us', 'vp', 'wq', '06', '17', '24', '35', '42', '53', '60', '71', '{}', '}{']

start_time = time.time()
CurrentBaseChunkAllPosTable = FridaBruteAllPossibleChunksForOne(FridaCracker, FinalFlag, 1)
# 记录结束时间
end_time = time.time()

# 计算运行时间
elapsed_time = end_time - start_time
print("CurrentBaseChunkAllPosTable: ", CurrentBaseChunkAllPosTable)
print(f"运行时间: {elapsed_time:.4f}秒")  # 格式化输出，最多保留4位小数
```



### 爆破出第三部分的可能性
发现要求的字符表存在大写字母，所以我们可以尝试大写字母的可能性，爆破出第三部分的可能性。

```python
from FridaCrackerModel import *

cmd = ['/home/kali/GithubProject/BruteReFlag/examples/example2/chall']
jscode = open("/home/kali/GithubProject/BruteReFlag/examples/example2/Hook.js", "rb").read().decode()
FridaCracker = FridaCrackerBase(cmd, jscode)

FinalFlag = FlagStruct(full_flag="", 
                       flag_prefix="flag",
                       flag_suffix="}",
                       flag_len=44,
                       flag_base_chunk_len=2)
globalmust_idx_value_pairs = []
globalcannot_idx_value_pairs = []

charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}'  # 定义字符集
length = 2  # 每个组合的长度
# 创建 BruteDataCombinations 实例
brute_data_combinations = BruteDataCombinations(charset, length)
# 将字符集和组合写入到文件
brute_data_combinations.write_charset_to_file()
# idx4,5 CurrentBaseChunkAllPosTable:  ['Ah', 'Bk', 'Cj', 'Dm', 'El', 'Fo', 'Gn', 'Ha', 'Jc', 'Kb', 'Le', 'Md', 'Ng', 'Of', 'Py', 'Qx', 'R{', 'Sz', 'T}', 'Xq', 'Yp', 'Zs', 'aH', 'bK', 'cJ', 'dM', 'eL', 'fO', 'gN', 'hA', 'jC', 'kB', 'lE', 'mD', 'nG', 'oF', 'pY', 'qX', 'sZ', 'xQ', 'yP', 'zS', '{R', '}T'] 运行时间: 211.7694秒
start_time = time.time()
CurrentBaseChunkAllPosTable = FridaBruteAllPossibleChunksForOne(FridaCracker, FinalFlag, 2)
# 记录结束时间
end_time = time.time()

# 计算运行时间
elapsed_time = end_time - start_time
print("CurrentBaseChunkAllPosTable: ", CurrentBaseChunkAllPosTable)
print(f"运行时间: {elapsed_time:.4f}秒")  # 格式化输出，最多保留4位小数
```

### 爆破出第四部分的可能性
根据前面的值可以得出:flag{R  是前缀,后面的都是单字节验证直接爆破即可。
```python
from FridaCrackerModel import *

cmd = ['/home/kali/GithubProject/BruteReFlag/examples/example2/chall']
jscode = open("/home/kali/GithubProject/BruteReFlag/examples/example2/Hook.js", "rb").read().decode()

BaseChunkNum = 1

FridaCracker = FridaCrackerBase(cmd, jscode)
FinalFlag = FlagStruct(full_flag="", 
                       flag_prefix="flag{ReAl1y_ez_cPp_vMach1n4_d0_YoU_L1k4_lT?^_^",
                       flag_suffix="",
                       flag_len=47,
                       flag_base_chunk_len=BaseChunkNum)
globalmust_idx_value_pairs = []
globalcannot_idx_value_pairs = []

charset = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ """  # 定义字符集
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
```



