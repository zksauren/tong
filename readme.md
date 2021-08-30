# tong

#### 介绍
基于envoy代理下的wasm waf插件

#### 软件目录架构
````
waf/
    README
    main.go                     > 主入口文件
    common/                     > 日志、服务获取库
    filter/                     > 过滤库
    internal/                   > 核心结构定义文件
    updater/                    > 规则更新库
````


**编译命令：**
`tinygo build -o ./envoy.wasm  -target=wasi ./main.go`

#### 使用说明 
* 本项目仅提供了wasm插件，插件运行所需的规则API需要读者自行实现。
* 日志由于wasm go sdk基本上个阶段不支持落本地磁盘日志，或者syslog等形式(阻塞的形式原理上均不允许)，本项目使用httpCall形式，请求ES API落日志。读者若想实验日志阶段，需自行配置ES，更改配置文件项。


#### 关于本项目

1.  envoy下wasm http filter插件仍处于实验阶段，本项目为实验学习性质，未经过实际测试，切勿用于正式环境。
2.  本项目使用tinygo编译，原生的go库很多无法使用，具体可用函数库参阅：
    `https://tinygo.org/docs/reference/lang-support/stdlib/`
3. tinygo对正则模块只能使用原生的regexp，插件运行出错，可能会导致envoy crash。

#### 引用的项目
* envoy下go wasm sdk  https://github.com/tetratelabs/proxy-wasm-go-sdk
* vjson https://github.com/vugu/vjson


