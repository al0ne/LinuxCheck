#!/bin/bash

echo -e "\e[00;31m系统信息\e[00m"
#当前用户
echo -e "USER:\t" `whoami` 2>/dev/null
#版本信息
source /etc/os-release
echo -e "OS Version:\t"  $PRETTY_NAME
#主机名
echo -e "Hostname: \t" `hostname -s`
# ipaddress
ipaddress=`ifconfig|ag -o '(?<=inet addr:)\d+\.\d+\.\d+\.\d+'|ag -v '127.0.0.1'` >/dev/null 2>&1
echo -e "IPADDR:\t$ipaddress"|sed ":a;N;s/\n/ /g;ta"
echo
echo -e "\e[00;31mCPU使用率:  \e[00m"
awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null  | while read line
do
    echo "$line" | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
        print$1" Free "free/total*100"%",\
        "Used " (total-free)/total*100"%"}'
done
echo
#CPU占用
cpu=`ps aux|grep -v ^'USER'|sort -rn -k3|head -10` 2>/dev/null
echo -e "\e[00;31mCPU TOP10:  \e[00m\n$cpu\n"
#内存占用
echo -e "\e[00;31m内存占用\e[00m"
free -mh
echo
#剩余空间
echo -e "\e[00;31m剩余空间\e[00m"
df -mh
echo
echo -e "\e[00;31m硬盘挂载\e[00m"
cat /etc/fstab|ag -v "#"|awk '{print $1,$2,$3}'
echo

#网络流量
echo -e "\e[00;31m网络流量 \e[00m"
echo "Interface    ByteRec   PackRec   ByteTran   PackTran"
awk   ' NR>2' /proc/net/dev  | while read line
do
    echo "$line" | awk -F ':' '{print "  "$1"  " $2}' |\
    awk '{print $1"   "$2 "    "$3"   "$10"  "$11}'
done
echo

#端口监听
echo -e "\e[00;31m端口监听\e[00m"
netstat -tulpen|ag 'tcp|udp.*' --nocolor
echo
#网络连接
echo -e "\e[00;31m网络连接\e[00m"
netstat -antop|ag ESTAB --nocolor
echo
#路由表
echo -e "\e[00;31m路由表\e[00m"
/sbin/route -nee
echo

#crontab
echo -e "\e[00;31mCrontab\e[00m"
crontab -u root -l|ag -v '#'
ls -al /etc/cron.*/*
echo

#passwd信息
echo -e "\e[00;31m用户信息查看\e[00m"
cat /etc/passwd|ag -v 'nologin$|false$'
echo -e "修改日期:" `stat /etc/passwd|ag -o '(?<=Modify: ).*' --nocolor`
echo -e "sudoers:" `cat /etc/sudoers|ag -v '#'|sed -e '/^$/d'|ag ALL --nocolor`
echo

#防火墙
echo -e "\e[00;31mIPTABLES防火墙\e[00m"
iptables -L
echo

#登陆信息
echo -e "\e[00;31m登录信息\e[00m"
last
lastlog
echo "登陆ip:" `ag -a accepted /var/log/auth.*|ag -o '\d+\.\d+\.\d+\.\d+'|sort|uniq`
echo

#运行服务
echo -e "\e[00;31mService \e[00m"
case $ID in
    debian|ubuntu|devuan)
        service --status-all |ag -Q '+' --nocolor
            ;;
    centos|fedora|rhel)
        service --status-all |ag -Q 'is running' --nocolor
            ;;
                    *)
     	exit 1
            ;;
   esac
echo

#查看history文件
echo -e "\e[00;31mHistory\e[00m"
ls -la ~/.*_history; ls -la /root/.*_history
echo

#tmp目录
echo -e "\e[00;31m/tmp \e[00m"
ls /tmp -al
echo

#近7天改动
echo -e "\e[00;31m近七天文件改动 \e[00m"
find /etc /bin /sbin /dev /root/  /home /tmp -mtime  -7|ag -v 'cache|vim'
echo

#lsmod 查看模块
echo -e "\e[00;31mlsmod模块\e[00m"
sudo lsmod
echo
