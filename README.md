# LinuxCheck

###
一个linux信息搜集小脚本 主要用于应急响应，在Debian或Centos下都可使用
### 功能

* CPU TOP10 、内存 TOP10
* CPU使用率
* 用户信息、passwd信息
* 环境变量检测
* 服务列表
* 系统改动（debsums -e与rpm -va）
* 网络连接、监听端口
* 路由表信息
* DNS Server
* 用户登陆信息
* iptables 信息
* SSH key 检测
* Crontab 检测
* 查找常见配置文件
* 审计history文件
* 查询HOSTS文件
* lsmod 异常内核模块
* 异常文件检测（nc、tunnel常见黑客工具）
* 大文件检测（打包的一些大文件）
* 剩余空间、硬盘挂载
* 对外开放端口
* LD_PRELOAD 检测
* 网卡混杂模式
* 常用软件
* 近7天改动文件
* 查看SUID文件
* 查找..隐藏文件
* alias别名
* 查找bash反弹shell
* php webshell扫描
* rkhunter 扫描

### Usage
apt-get install silversearcher-ag  
bash -c "$(curl -sSL https://raw.githubusercontent.com/al0ne/LinuxCheck/master/LinuxCheck.sh)"  
文件会保存成ipaddr_hostname_username_timestamp.log 这种格式

### 参考

Linenum    
https://github.com/lis912/Evaluation_tools   
https://ixyzero.com/blog/archives/4.html    
https://github.com/T0xst/linux    
