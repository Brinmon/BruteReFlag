var number = 0

function main()
{
    	var base =  Module.findBaseAddress("nor.nor")
        var st = Memory.allocUtf8String("Suprise!");//申请一片内存来存放字符串
        var f = new NativeFunction(ptr(base.add(0x1090)),'void',['pointer']);//获取到printf的函数地址并且声明为函数！
        Interceptor.attach(ptr(base.add(0x179D)), {//序号加1的位置
            onEnter: function(args) {
            	number += 1;
            }
        });
        
        Interceptor.attach(ptr(base.add(0x178C)), {//程序退出的位置
            onEnter: function(args) {
		    send(number);
            var delay = 0x20;
                    var start = new Date().getTime();
                    while (new Date().getTime() < start + delay);
                }
            });
        Interceptor.attach(ptr(base.add(0x1831)), {//成功的地方
            onEnter: function(args) {
		    send(number);
            var delay = 0x20;
                    var start = new Date().getTime();
                    while (new Date().getTime() < start + delay);
                }
            });

}
setImmediate(main);