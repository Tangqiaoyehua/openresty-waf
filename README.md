# openresty-waf
&emsp;&emsp;**A WAF program based on openresty.**

&emsp;&emsp;打算从零开始基于openresty做一个waf项目练练手，其实GitHub上已经有很多这种项目了，而且还很成熟了，但是这个项目只是用来练手，不过也要有亮点，就是代码真·易读，估计做这个东西的周期会很长。

## 1.安装

*注：目前仅限于linux*

&emsp;&emsp;下载最新的openresty压缩包，按照官网的随便安装两下就行了。

## 2.功能及测试
*注：功能及模块配置见conf/conf.json*

&emsp;&emsp;防CC：使用jmeter压测。

&emsp;&emsp;慢速攻击：github上有一个项目slowhttptest可以用来测试

&emsp;&emsp;防注入：dvwa平台，不用平台也可以，自定义注入命令访问也可以。

&emsp;&emsp;防爬虫：jmeter自定义ua

&emsp;&emsp;黑白名单：黑名单为-1，白名单为1
