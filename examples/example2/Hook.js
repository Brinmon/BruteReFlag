var number = 0

function main() {
    var base = Module.findBaseAddress("chall");
    // 序号加1的位置
    Interceptor.attach(ptr(base.add(0x1BAC)), {
        onEnter: function(args) {
            number += 1;
        }
    });

    // 程序退出的位置
    Interceptor.attach(ptr(base.add(0x1B7E)), {
        onEnter: function(args) {
            send(number)
            var delay = 0x20;
            var start = new Date().getTime();
            while (new Date().getTime() < start + delay); //这个也是关键点
        }
    });

    // // 成功的地方
    // Interceptor.attach(ptr(base.add(0x1BB3)), {
    //     onEnter: function(args) {
    //         send(number);
    //     }
    // });
}

setImmediate(main);
