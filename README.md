# LinuxCheck

###
一个linux信息搜集小脚本 主要用于应急响应，在Debian或Centos下都可使用
### 功能

* 信息搜集（端口、网络、用户信息、登陆信息，iptables、各种环境变量或配置文件等）
* 异常检测（CPU占用，内存占用，大文件，异常内核模块，最近改动文件，SSH key，crontab，以及Linux常见后门检测）
* rkhunter扫描
* php webshell扫描
### Usage
apt-get install silversearcher-ag  
bash -c "$(curl -sSL https://raw.githubusercontent.com/al0ne/LinuxCheck/master/LinuxCheck.sh)"

### 参考

Linenum    
https://github.com/lis912/Evaluation_tools   
https://ixyzero.com/blog/archives/4.html    
https://github.com/T0xst/linux    
