#!/usr/bin/env bash

echo ""
echo " ========================================================= "
echo " \        Linux应急处置/信息搜集/漏洞检测脚本 V2.3      / "
echo " ========================================================= "
echo " # 支持Centos、Debian系统检测                    "
echo " # author：al0ne                    "
echo " # https://github.com/al0ne                    "
echo " # 更新日期：2022年08月5日                    "
echo " # 参考来源：                "
echo " #   1.Gscan https://github.com/grayddq/GScan  "
echo " #   2.Lynis https://github.com/CISOfy/lynis  "
echo -e "\n"

# 更新日志：2022年08月05日
#### 修复内核模块检查日志过多问题
# 更新日志：2022年03月07日
#### 添加SSH软连接后门检测
# 更新日期：2021年10月17日
#### 添加Ntpclient/WorkMiner/TeamTNT挖矿木马检测
#### 添加Rootkit模块检测逻辑
#### 添加Python pip投毒检测
#### 添加$HOME/.profile查看
#### 添加服务器风险检查(Redis)

# WEB Path 设置web目录 默认的话是从/目录去搜索 性能较慢
webpath='/'

print_msg() {
  echo -e "\e[00;31m[+]$1\e[00m"
}

### 1.环境检查 ###
print_msg "环境检测"
# 验证是否为root权限
if [ $UID -ne 0 ]; then
  print_msg "请使用root权限运行!"
  exit 1
else
  print_msg "当前为root权限"
fi

# 验证操作系统是debian系还是centos
OS='None'

if [ -e "/etc/os-release" ]; then
  source /etc/os-release
  case ${ID} in
  "debian" | "ubuntu" | "devuan")
    OS='Debian'
    ;;
  "centos" | "rhel fedora" | "rhel")
    OS='Centos'
    ;;
  *) ;;
  esac
fi

if [ $OS = 'None' ]; then
  if command -v apt-get >/dev/null 2>&1; then
    OS='Debian'
  elif command -v yum >/dev/null 2>&1; then
    OS='Centos'
  else
    echo -e "\n不支持这个系统\n"
    echo -e "已退出"
    exit 1
  fi
fi

# 安装应急必备工具
cmdline=(
  "net-tools"
  "telnet"
  "nc"
  "lrzsz"
  "wget"
  "strace"
  "traceroute"
  "htop"
  "tar"
  "lsof"
  "tcpdump"
)
for prog in "${cmdline[@]}"; do

  if [ $OS = 'Centos' ]; then
    soft=$(rpm -q "$prog")
    if echo "$soft" | grep -E '没有安装|未安装|not installed' >/dev/null 2>&1; then
      echo -e "$prog 安装中......"
      yum install -y "$prog" >/dev/null 2>&1
      yum install -y the_silver_searcher >/dev/null 2>&1
    fi
  else
    if dpkg -L $prog | grep 'does not contain any files' >/dev/null 2>&1; then
      echo -e "$prog 安装中......"
      apt install -y "$prog" >/dev/null 2>&1
      apt install -y silversearcher-ag >/dev/null 2>&1
    fi

  fi
done

echo -e "\n"

# 设置保存文件
ipaddress=$(ip address | ag -o '(?<=inet )\d+\.\d+\.\d+\.\d+(?=\/2)' | head -n 1)
filename=$ipaddress'_'$(hostname)'_'$(whoami)'_'$(date +%s)_log'.log'
vuln="$ipaddress_$(hostname)_$(whoami)_$(date +%s)_vuln.log"

base_check() {
  echo -e "############ 基础配置检查 ############\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]系统信息\e[00m" | tee -a "$filename"
  #当前用户
  echo -e "USER:\t\t$(whoami)" 2>/dev/null | tee -a "$filename"
  #版本信息
  echo -e "OS Version:\t$(uname -r)" | tee -a "$filename"
  #主机名
  echo -e "Hostname: \t$(hostname -s)" | tee -a "$filename"
  #服务器SN
  echo -e "服务器SN: \t$(dmidecode -t1 | ag -o '(?<=Serial Number: ).*')" | tee -a "$filename"
  #uptime
  echo -e "Uptime: \t$(uptime | awk -F ',' '{print $1}')" | tee -a "$filename"
  #系统负载
  echo -e "系统负载: \t$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')" | tee -a "$filename"
  #cpu信息
  echo -e "CPU info:\t$(ag -o '(?<=model name\t: ).*' </proc/cpuinfo | head -n 1)" | tee -a "$filename"
  #cpu核心
  echo -e "CPU 核心:\t$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)" | tee -a "$filename"
  #ipaddress
  ipaddress=$(ifconfig | ag -o '(?<=inet |inet addr:)\d+\.\d+\.\d+\.\d+' | ag -v '127.0.0.1') >/dev/null 2>&1
  echo -e "IPADDR:\t\t${ipaddress}" | sed ":a;N;s/\n/ /g;ta" | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]CPU使用率:  \e[00m" | tee -a "$filename"
  awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null | while read line; do
    echo "$line" | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
        print$1" Free "free/total*100"%",\
        "Used " (total-free)/total*100"%"}' | tee -a "$filename"
  done
  echo -e "\n" | tee -a "$filename"
  #登陆用户
  echo -e "\e[00;31m[+]登陆用户\e[00m" | tee -a "$filename"
  who | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #CPU占用TOP 15
  cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -15) 2>/dev/null
  echo -e "\e[00;31m[+]CPU TOP15:  \e[00m\n${cpu}\n" | tee -a "$filename"
  #内存占用TOP 15
  mem=$(ps aux | grep -v ^'USER' | sort -rn -k4 | head -15) 2>/dev/null
  echo -e "\e[00;31m[+]内存占用 TOP15:  \e[00m\n${mem}\n" | tee -a "$filename"
  #内存占用
  echo -e "\e[00;31m[+]内存占用\e[00m" | tee -a "$filename"
  free -mh | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #剩余空间
  echo -e "\e[00;31m[+]剩余空间\e[00m" | tee -a "$filename"
  df -mh | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]硬盘挂载\e[00m" | tee -a "$filename"
  ag -v "#" </etc/fstab | awk '{print $1,$2,$3}' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #安装软件
  echo -e "\e[00;31m[+]常用软件\e[00m" | tee -a "$filename"
  cmdline=(
    "which perl"
    "which gcc"
    "which g++"
    "which python"
    "which php"
    "which cc"
    "which go"
    "which node"
    "which nodejs"
    "which bind"
    "which tomcat"
    "which clang"
    "which ruby"
    "which curl"
    "which wget"
    "which mysql"
    "which redis"
    "which ssserver"
    "which vsftpd"
    "which java"
    "which apache"
    "which apache2"
    "which nginx"
    "which git"
    "which mongodb"
    "which docker"
    "which tftp"
    "which psql"
    "which kafka"

  )

  for prog in "${cmdline[@]}"; do
    soft=$($prog)
    if [ "$soft" ] 2>/dev/null; then
      echo -e "$soft" | ag -o '\w+$' --nocolor | tee -a "$filename"
    fi
  done
  echo -e "\n" | tee -a "$filename"
  #HOSTS
  echo -e "\e[00;31m[+]/etc/hosts \e[00m" | tee -a "$filename"
  cat /etc/hosts | ag -v "#" | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
}

network_check() {
  echo -e "############ 网络/流量检查 ############\n" | tee -a "$filename"
  #ifconfig
  echo -e "\e[00;31m[+]ifconfig\e[00m" | tee -a "$filename"
  /sbin/ifconfig -a | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #网络流量
  echo -e "\e[00;31m[+]网络流量 \e[00m" | tee -a "$filename"
  echo "Interface    ByteRec   PackRec   ByteTran   PackTran" | tee -a "$filename"
  awk ' NR>2' /proc/net/dev | while read line; do
    echo "$line" | awk -F ':' '{print "  "$1"  " $2}' |
      awk '{print $1"   "$2 "    "$3"   "$10"  "$11}' | tee -a "$filename"
  done
  echo -e "\n" | tee -a "$filename"
  #端口监听
  echo -e "\e[00;31m[+]端口监听\e[00m" | tee -a "$filename"
  netstat -tulpen | ag 'tcp|udp.*' --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #对外开放端口
  echo -e "\e[00;31m[+]对外开放端口\e[00m" | tee -a "$filename"
  netstat -tulpen | awk '{print $1,$4}' | ag -o '.*0.0.0.0:(\d+)|:::\d+' --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #网络连接
  echo -e "\e[00;31m[+]网络连接\e[00m" | tee -a "$filename"
  netstat -antop | ag ESTAB --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #连接状态
  echo -e "\e[00;31m[+]TCP连接状态\e[00m" | tee -a "$filename"
  netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #路由表
  echo -e "\e[00;31m[+]路由表\e[00m" | tee -a "$filename"
  /sbin/route -nee | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #路由转发
  echo -e "\e[00;31m[+]路由转发\e[00m" | tee -a "$filename"
  ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}')
  if [ -n "$ip_forward" ]; then
    echo "/proc/sys/net/ipv4/ip_forward 已开启路由转发" | tee -a "$filename"
  else
    echo "该服务器未开启路由转发" | tee -a "$filename"
  fi
  echo -e "\n" | tee -a "$filename"
  #DNS
  echo -e "\e[00;31m[+]DNS Server\e[00m" | tee -a "$filename"
  ag -o '\d+\.\d+\.\d+\.\d+' --nocolor </etc/resolv.conf | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #ARP
  echo -e "\e[00;31m[+]ARP\e[00m" | tee -a "$filename"
  arp -n -a | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #混杂模式
  echo -e "\e[00;31m[+]网卡混杂模式\e[00m" | tee -a "$filename"
  if ip link | ag PROMISC >/dev/null 2>&1; then
    echo "网卡存在混杂模式！" | tee -a "$filename"
  else
    echo "网卡不存在混杂模式" | tee -a "$filename"

  fi
  echo -e "\n" | tee -a "$filename"
  #防火墙
  echo -e "\e[00;31m[+]IPTABLES防火墙\e[00m" | tee -a "$filename"
  iptables -L | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
}

crontab_check() {
  echo -e "############ 任务计划检查 ############\n" | tee -a "$filename" | tee -a "$vuln"
  #crontab
  echo -e "\e[00;31m[+]Crontab\e[00m" | tee -a "$filename"
  crontab -u root -l | ag -v '#' --nocolor | tee -a "$filename"
  ls -alht /etc/cron.*/* | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"

  #crontab可疑命令
  echo -e "\e[00;31m[+]Crontab Backdoor \e[00m" | tee -a "$vuln"
  ag '((?:useradd|groupadd|chattr)|(?:wget\s|curl\s|tftp\s\-i|scp\s|sftp\s)|(?:bash\s\-i|fsockopen|nc\s\-e|sh\s\-i|\"/bin/sh\"|\"/bin/bash\"))' /etc/cron* /var/spool/cron/* --nocolor | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

env_check() {
  echo -e "############ 环境变量检查 ############\n" | tee -a "$filename"
  #env
  echo -e "\e[00;31m[+]env\e[00m" | tee -a "$filename"
  env | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #PATH
  echo -e "\e[00;31m[+]PATH\e[00m" | tee -a "$filename"
  echo "$PATH" | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #LD_PRELOAD
  echo -e "\e[00;31m[+]LD_PRELOAD\e[00m" | tee -a "$vuln"
  echo ${LD_PRELOAD} | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #LD_ELF_PRELOAD
  echo -e "\e[00;31m[+]LD_ELF_PRELOAD\e[00m" | tee -a "$vuln"
  echo ${LD_ELF_PRELOAD} | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #LD_AOUT_PRELOAD
  echo -e "\e[00;31m[+]LD_AOUT_PRELOAD\e[00m" | tee -a "$vuln"
  echo ${LD_AOUT_PRELOAD} | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #PROMPT_COMMAND
  echo -e "\e[00;31m[+]PROMPT_COMMAND\e[00m" | tee -a "$vuln"
  echo "${PROMPT_COMMAND}" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #LD_LIBRARY_PATH
  echo -e "\e[00;31m[+]LD_LIBRARY_PATH\e[00m" | tee -a "$vuln"
  echo "${LD_LIBRARY_PATH}" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #ld.so.preload
  echo -e "\e[00;31m[+]ld.so.preload\e[00m" | tee -a "$vuln"
  preload='/etc/ld.so.preload'
  if [ -e "${preload}" ]; then
    cat ${preload} | tee -a "$vuln"
  fi
  echo -e "\n" | tee -a "$vuln"
}

user_check() {
  echo -e "############ 用户信息检查 ############\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]可登陆用户\e[00m" | tee -a "$filename"
  cat /etc/passwd | ag -v 'nologin$|false$' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]passwd文件修改日期: \e[00m" $(stat /etc/passwd | ag -o '(?<=Modify: ).*' --nocolor) | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]sudoers(请注意NOPASSWD)\e[00m" | tee -a "$filename"
  cat /etc/sudoers | ag -v '#' | sed -e '/^$/d' | ag ALL --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]登录信息\e[00m" | tee -a "$filename"
  w | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  last | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  lastlog | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo "登陆ip: $(ag -a accepted /var/log/secure /var/log/auth.* 2>/dev/null | ag -o '\d+\.\d+\.\d+\.\d+' | sort | uniq)" | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
}

service_check() {
  echo -e "############ 服务状态检查 ############\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]正在运行的Service \e[00m" | tee -a "$filename"
  systemctl -l | grep running | awk '{print $1}' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]最近添加的Service \e[00m" | tee -a "$filename"
  ls -alhtR /etc/systemd/system/multi-user.target.wants | tee -a "$filename"
  ls -alht /etc/systemd/system/*.service | ag -v 'dbus-org' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
}

bash_check() {
  echo -e "######Bash配置检查######\n" | tee -a "$filename"
  #查看history文件
  echo -e "\e[00;31m[+]History\e[00m" | tee -a "$filename"
  ls -alht /root/.*_history | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  cat ~/.*history | ag '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])|http://|https://|\bssh\b|\bscp\b|\.tar|\bwget\b|\bcurl\b|\bnc\b|\btelnet\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b|/etc/passwd|/etc/shadow|/etc/hosts|\bnmap\b|\bfrp\b|\bnfs\b|\bsshd\b|\bmodprobe\b|\blsmod\b|\bsudo\b' --nocolor | ag -v 'man\b|ag\b|cat\b|sed\b|git\b|docker\b|rm\b|touch\b|mv\b|\bapt\b|\bapt-get\b' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #/etc/profile
  echo -e "\e[00;31m[+]/etc/profile \e[00m" | tee -a "$filename"
  cat /etc/profile | ag -v '#' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  # $HOME/.profile
  echo -e "\e[00;31m[+]\$HOME/.profile \e[00m" | tee -a "$filename"
  cat $HOME/.profile | ag -v '#' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #/etc/rc.local
  echo -e "\e[00;31m[+]/etc/rc.local \e[00m" | tee -a "$filename"
  cat /etc/rc.local | ag -v '#' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #~/.bash_profile
  echo -e "\e[00;31m[+]~/.bash_profile \e[00m" | tee -a "$filename"
  if [ -e "$HOME/.bash_profile" ]; then
    cat ~/.bash_profile | ag -v '#' | tee -a "$filename"
  fi
  echo -e "\n" | tee -a "$filename"
  #~/.bashrc
  echo -e "\e[00;31m[+]~/.bashrc \e[00m" | tee -a "$filename"
  cat ~/.bashrc | ag -v '#' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #bash反弹shell
  echo -e "\e[00;31m[+]bash反弹shell \e[00m" | tee -a "$vuln"
  ps -ef | ag 'bash -i' | ag -v 'ag' | awk '{print $2}' | xargs -i{} lsof -p {} | ag 'ESTAB' --nocolor | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

file_check() {
  echo -e "############ 文件检查 ############\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]系统文件修改时间 \e[00m" | tee -a "$vuln"
  cmdline=(
    "/sbin/ifconfig"
    "/bin/ls"
    "/bin/login"
    "/bin/netstat"
    "/bin/top"
    "/bin/ps"
    "/bin/find"
    "/bin/grep"
    "/etc/passwd"
    "/etc/shadow"
    "/usr/bin/curl"
    "/usr/bin/wget"
    "/root/.ssh/authorized_keys"
  )
  for soft in "${cmdline[@]}"; do
    echo -e "文件：$soft\t\t\t修改日期：$(stat $soft | ag -o '(?<=Modify: )[\d-\s:]+')" | tee -a "$vuln"
  done

  echo -e "\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]...隐藏文件 \e[00m" | tee -a "$vuln"
  find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*." | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #tmp目录
  echo -e "\e[00;31m[+]/tmp \e[00m" | tee -a "$filename"
  # shellcheck disable=SC2012
  ls /tmp /var/tmp /dev/shm -alht | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #alias 别名
  echo -e "\e[00;31m[+]alias \e[00m" | tee -a "$filename"
  alias | ag -v 'git' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #SUID
  echo -e "\e[00;31m[+]SUID \e[00m" | tee -a "$vuln"
  find / ! -path "/proc/*" -perm -004000 -type f | ag -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps' | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #lsof -L1
  #进程存在但文件已经没有了
  echo -e "\e[00;31m[+]lsof +L1 \e[00m" | tee -a "$filename"
  lsof +L1 | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #近7天改动
  echo -e "\e[00;31m[+]近七天文件改动 mtime \e[00m" | tee -a "$filename"
  find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -mtime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {} | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #近7天改动
  echo -e "\e[00;31m[+]近七天文件改动 ctime \e[00m" | tee -a "$filename"
  find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {} | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #大文件100mb
  #有些黑客会将数据库、网站打包成一个文件然后下载
  echo -e "\e[00;31m[+]大文件>200mb \e[00m" | tee -a "$filename"
  find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +200M -exec ls -alht {} + 2>/dev/null | ag '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' --nocolor | ag -v 'ib_logfile|ibd|mysql-bin|mysql-slow|ibdata1' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #敏感文件
  echo -e "\e[00;31m[+]敏感文件 \e[00m" | tee -a "$vuln"
  find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*tunnel\.(php|jsp|asp|py)|.*/nc\b|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc|.*aircrack|.*hydra|.*miner|.*/ew$' -type f | ag -v '/lib/python' | xargs -i{} ls -alh {} | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]可疑黑客文件 \e[00m" | tee -a "$vuln"
  find /root /home /opt /tmp /var/ /dev -regextype posix-extended -regex '.*wget|.*curl|.*openssl|.*mysql' -type f 2>/dev/null | xargs -i{} ls -alh {} | ag -v '/pkgs/|/envs/' | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

rootkit_check() {
  echo -e "############ Rootkit检查 ############\n" | tee -a "$vuln"
  #lsmod 可疑模块
  echo -e "\e[00;31m[+]lsmod 可疑模块\e[00m" | tee -a "$vuln"
  lsmod | ag -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|ip6table_raw|skx_edac|intel_rapl|wmi|acpi_pad|ast|i40e|ptp|nfit|libnvdimm|bpfilter|failover" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]Rootkit 内核模块\e[00m" | tee -a "$vuln"
  kernel=$(grep -E 'hide_tcp4_port|hidden_files|hide_tcp6_port|diamorphine|module_hide|module_hidden|is_invisible|hacked_getdents|hacked_kill|heroin|kernel_unlink|hide_module|find_sys_call_tbl|h4x_delete_module|h4x_getdents64|h4x_kill|h4x_tcp4_seq_show|new_getdents|old_getdents|should_hide_file_name|should_hide_task_name' </proc/kallsyms)
  if [ -n "$kernel" ]; then
    echo "存在内核敏感函数！疑似Rootkit内核模块" | tee -a "$vuln"
    echo "$kernel" | tee -a "$vuln"
  else
    echo "未找到内核敏感函数" | tee -a "$vuln"
  fi
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]可疑的.ko模块\e[00m" | tee -a "$vuln"
  find / ! -path "/proc/*" ! -path "/usr/lib/modules/*" ! -path "/lib/modules/*" ! -path "/boot/*" -regextype posix-extended -regex '.*\.ko' | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

ssh_check() {
  echo -e "############ SSH检查 ############\n" | tee -a "$filename"
  #SSH爆破IP
  echo -e "\e[00;31m[+]SSH爆破\e[00m" | tee -a "$filename"
  if [ $OS = 'Centos' ]; then
    ag -a 'authentication failure' /var/log/secure* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25 | tee -a "$filename"
  else
    ag -a 'authentication failure' /var/log/auth.* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25 | tee -a "$filename"
  fi
  echo -e "\n" | tee -a "$filename"
  #SSHD
  echo -e "\e[00;31m[+]SSHD \e[00m" | tee -a "$filename"
  echo -e "/usr/sbin/sshd"
  stat /usr/sbin/sshd | ag 'Access|Modify|Change' --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"

  #ssh后门配置检查
  echo -e "\e[00;31m[+]SSH 后门配置 \e[00m" | tee -a "$vuln"
  if [ -e "$HOME/.ssh/config" ]; then
    grep LocalCommand <~/.ssh/config | tee -a "$vuln"
    grep ProxyCommand <~/.ssh/config | tee -a "$vuln"
  else
    echo -e "未发现ssh配置文件" | tee -a "$vuln"
  fi
  echo -e "\n" | tee -a "$vuln"

  #ssh后门配置检查
  echo -e "\e[00;31m[+]SSH 软连接后门 \e[00m" | tee -a "$vuln"
  if ps -ef | ag '\s+\-oport=\d+' >/dev/null 2>&1; then
    ps -ef | ag '\s+\-oport=\d+' | tee -a "$vuln"
  else
    echo "未检测到SSH软连接后门" | tee -a "$vuln"

  fi
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]SSH inetd后门检查 \e[00m" | tee -a "$vuln"
  if [ -e "/etc/inetd.conf" ]; then
    grep -E '(bash -i)' </etc/inetd.conf | tee -a "$vuln"
  fi
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]SSH key\e[00m" | tee -a "$vuln"
  sshkey=${HOME}/.ssh/authorized_keys
  if [ -e "${sshkey}" ]; then
    # shellcheck disable=SC2002
    cat ${sshkey} | tee -a "$vuln"
  else
    echo -e "SSH key文件不存在\n" | tee -a "$vuln"
  fi
  echo -e "\n" | tee -a "$vuln"
}

webshell_check() {
  echo -e "############ Webshell检查 ############\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]PHP webshell查杀\e[00m" | tee -a "$vuln"
  ag --php -l -s -i 'array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\(' $webpath | tee -a "$vuln"
  ag --php -l -s -i '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php' $webpath | tee -a "$vuln"
  ag --php -l -s -i '\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))' $webpath | tee -a "$vuln"
  ag --php -l -s -i '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))' $webpath | tee -a "$vuln"
  ag --php -l -s -i '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))' $webpath | tee -a "$vuln"
  ag --php -l -s -i "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input" $webpath | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #JSP webshell查杀
  echo -e "\e[00;31m[+]JSP webshell查杀\e[00m" | tee -a "$vuln"
  ag --jsp -l -s -i '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)' $webpath | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

poison_check() {
  echo -e "############ 供应链投毒检测 ############\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]Python2 pip 检测\e[00m" | tee -a "$vuln"
  pip freeze | ag "istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]Python3 pip 检测\e[00m" | tee -a "$vuln"
  pip3 freeze | ag "istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

miner_check() {
  echo -e "############ 挖矿木马检查 ############\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]常规挖矿进程检测\e[00m" | tee -a "$vuln"
  ps aux | ag "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb" | ag -v 'ag' | tee -a "$vuln"
  find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -regextype posix-extended -regex '.*systemctI|.*kworkerds|.*init10.cfg|.*wl.conf|.*crond64|.*watchbog|.*sustse|.*donate|.*proxkekman|.*cryptonight|.*sustes|.*xmrig|.*xmr-stak|.*suppoie|.*ririg|gg1.conf|.*cpuminer|.*xmr|.*xig|.*ddgs|.*minerd|.*hashvault|\.kthreadd|.*httpdz|.*kerbero|.*2t3ik|.*qW3xt|.*ztctb|.*miner.sh' -type f | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]Ntpclient 挖矿木马检测\e[00m" | tee -a "$vuln"
  find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/boot/*" -regextype posix-extended -regex 'ntpclient|Mozz' | tee -a "$vuln"
  ls -alh /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]WorkMiner 挖矿木马检测\e[00m" | tee -a "$vuln"
  ps aux | ag "work32|work64|/tmp/secure.sh|/tmp/auth.sh" | ag -v 'ag'
  ls -alh /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

risk_check() {
  echo -e "############ 服务器风险/漏洞检查 ############\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]Redis弱密码检测\e[00m" | tee -a "$vuln"
  cat /etc/redis/redis.conf 2>/dev/null | ag '(?<=requirepass )(test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888)' | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

base_check
network_check
crontab_check
env_check
user_check
service_check
bash_check
file_check
rootkit_check
ssh_check
webshell_check
poison_check
miner_check
risk_check
