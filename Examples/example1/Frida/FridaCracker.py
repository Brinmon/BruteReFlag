import subprocess
import frida
import time

flaglen = 0x2a
flag = bytearray(b'!' * flaglen)
filename = "nor.nor"
cmd = ['/home/kali/GithubProject/BruteReFlag/examples/example1/nor.nor']
jscode = open("Hook.js", "rb").read().decode()


result = 0
def brute(F):

    def on_message(message, data):
        global result
        if message['type'] == 'send':
            result = message['payload']
        else:
            print(message)
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               universal_newlines=True)

    session = frida.attach(filename)
    script = session.create_script(jscode)
    script.on('message', on_message)
    script.load()
    process.stdin.write(F.decode())

    output, error = process.communicate()
    process.terminate()
    return result
print("开始！")
count = 0
new_number = brute(flag)
number = new_number
t = time.time()
st = t

while count < flaglen:
    number = brute(flag)
    if number > new_number:
        print(f"本位耗时:{time.time()-t}s,正确字符为：{chr(flag[count])}")
        t = time.time()
        print(flag.decode())
        new_number = number
        count += 1
    else:
        flag[count] += 1
        while(flag[count] > 127):
            flag[count] = 33
            count -= 1
            flag[count] += 1
print("最终flag！",flag.decode())
print(f"总耗时{time.time()-st}")
