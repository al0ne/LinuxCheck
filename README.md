# LinuxCheck

###
一个linux信息搜集小脚本 主要用于应急响应，在Debian或Centos下都可使用
### 功能

* CPU TOP10 、内存 TOP10
* CPU使用率
* 开机时间
* 硬盘空间信息
* 用户信息、passwd信息
* 环境变量检测
* 服务列表
* 系统程序改动（debsums -e与rpm -va）
* 网络流量统计
* 网络连接、监听端口
* 对外开放端口
* 路由表信息
* 路由转发
* ARP
* DNS Server
* SSH登陆信息
* SSH登陆IP
* iptables 信息
* SSH key 检测
* SSH 爆破IP
* Crontab 检测
* Crontab 后门检测
* 查找常见配置文件
* 查找常用软件
* 审计history文件
* 查询HOSTS文件
* lsmod 异常内核模块
* 异常文件检测（nc、tunnel、proxy常见黑客工具）
* 大文件检测（打包的一些大文件）
* 剩余空间、硬盘挂载
* 对外开放端口
* LD_PRELOAD 检测
* LD_LIBRARY_PATH
* ld.so.preload
* 网卡混杂模式
* 常用软件
* 近7天改动文件mtime
* 近7天改动文件ctime
* 查看SUID文件
* 查找..隐藏文件
* 查找敏感文件（nc、nmap、tunnel）
* alias别名
* LSOF -L1
* SSHD
* 查找bash反弹shell
* php webshell扫描
* jsp webshell扫描
* asp/aspx webshell扫描
* 挖矿进程检测
* rkhunter 扫描

### Usage

联网状态：
 - apt-get install silversearcher-ag
 - yum -y install the_silver_searcher  

离线状态：   
 - Debian：dpkg -i silversearcher-ag_2.2.0-1+b1_amd64.deb  
 - Centos：rpm -ivh the_silver_searcher-2.1.0-1.el7.x86_64.rpm  

git clone https://github.com/al0ne/LinuxCheck.git  
chmod u+x LinuxCheck.sh  
./LinuxCheck.sh  
如果已经安装了ag和rkhunter可以直接使用以下命令  
bash -c "$(curl -sSL https://raw.githubusercontent.com/al0ne/LinuxCheck/master/LinuxCheck.sh)"  
文件会保存成ipaddr_hostname_username_timestamp.log 这种格式

### 参考

Linenum    
https://github.com/lis912/Evaluation_tools   
https://ixyzero.com/blog/archives/4.html    
https://github.com/T0xst/linux  
https://github.com/grayddq/GScan  
