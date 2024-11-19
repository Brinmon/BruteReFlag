var number = 0

function main()
{
    	var base =  Module.findBaseAddress("nor.nor")
        Interceptor.attach(ptr(base.add(0x179D)), {//序号加1的位置
            onEnter: function(args) {
            	number += 1;
            }
        });
        
        Interceptor.attach(ptr(base.add(0x178C)), { // 程序退出的位置
            onEnter: function(args) {
                // 创建要发送的信息对象
                var infoToSend = {
                    number: number,
                    additionalInfo1: "附加信息1",   // 示例附加信息
                };
                
                // 发送信息对象
                send(infoToSend);

                // 控制延迟
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