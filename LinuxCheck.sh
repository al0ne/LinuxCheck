#!/usr/bin/env bash

echo ""
echo " ========================================================= "
echo " \        Linux应急处置/信息搜集/漏洞检测脚本 V3.0      / "
echo " ========================================================= "
echo " # 支持Centos、Debian系统检测                    "
echo " # author：al0ne                    "
echo " # https://github.com/al0ne                    "
echo " # 更新日期：2024年4月20日                    "
echo " # 参考来源：                "
echo " #   1.Gscan https://github.com/grayddq/GScan  "
echo " #   2.Lynis https://github.com/CISOfy/lynis  "
echo " #   3.container-escape-check https://github.com/teamssix/container-escape-check"
echo -e "\n"

# WEB Path 设置web目录，检测Webshell。
webpath='/'

# 报告上报的地址
webhook_url='http://localhost:5000/upload'

# 设置保存文件
ipaddress=$(ip address | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+(?=\/2)' | head -n 1)
filename=$ipaddress'_'$(hostname)'_'$(whoami)'_'$(date +%s)_log'.md'

print_msg() {
  echo -e "$1\n" | tee -a $filename
}

print_code() {
  echo -e "\`\`\`shell\n$1\n\`\`\`\n" | tee -a $filename
}

reverse_shell_check() {
  echo -e "\n"
  print_code "$(grep -P '(tftp\s\-i|scp\s|sftp\s|bash\s\-i|nc\s\-e|sh\s\-i|wget\s|curl\s|\bexec|/dev/tcp/|/dev/udp/)' $1 $2 $3)"
  print_code "$(grep -P '(useradd|groupadd|chattr|fsockopen|socat|base64|socket|perl|openssl)' $1 $2 $3)"
}

### 1.环境检查 ###
print_msg "## 环境检测"
# 验证是否为root权限
if [ $UID -ne 0 ]; then
  print_msg "请使用root权限运行！"
  exit 1
else
  print_msg "当前为root权限！"
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
    fi

  fi
done

echo -e "\n"

base_check() {
  print_msg "## 基础配置检查"
  print_msg "### 系统信息"
  #当前用户
  print_msg "**USER:**\t\t$(whoami)" 2>/dev/null
  #版本信息
  print_msg "**OS Version:**\t$(uname -r)"
  #主机名
  print_msg "**Hostname:** \t$(hostname -s)"
  #服务器SN
  print_msg "**服务器SN:** \t$(dmidecode -t1 | grep -oP '(?<=Serial Number: ).*')"
  #uptime
  print_msg "**Uptime:** \t$(uptime | awk -F ',' '{print $1}')"
  #系统负载
  print_msg "**系统负载:** \t$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')"
  #cpu信息
  print_msg "**CPU info:**\t$(grep -oP '(?<=model name\t: ).*' </proc/cpuinfo | head -n 1)"
  #cpu核心
  print_msg "**CPU 核心:**\t$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)"
  #ipaddress
  ipaddress=$(ifconfig | grep -oP '(?<=inet |inet addr:)\d+\.\d+\.\d+\.\d+' | grep -v '127.0.0.1') >/dev/null 2>&1
  print_msg "**IPADDR:**\t\t${ipaddress}" | sed ":a;N;s/\n/ /g;ta"
  print_msg "**CPU使用率:**  "
  awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null | while read line; do
    print_msg "$(echo $line | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
        print$1" Free "free/total*100"%",\
        "Used " (total-free)/total*100"%"}')"
  done

  #内存占用
  print_msg "### 内存占用"
  print_code "$(free -mh)"

  #剩余空间
  print_msg "### 剩余空间"
  print_code "$(df -mh)"

  print_msg "### 硬盘挂载"
  print_code "$(grep -v '#' </etc/fstab | awk '{print $1,$2,$3}')"

  #安装软件
  # print_msg "### 常用软件"
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

  #HOSTS
  print_msg "### /etc/hosts"
  print_code "$(cat /etc/hosts | egrep -v "#")"
}

process_check() {
  print_msg "## 进程信息检查"

  print_msg "### CPU占用TOP 15"
  cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -15) 2>/dev/null
  print_code "${cpu}"

  print_msg "### 内存占用TOP 15"
  mem=$(ps aux | grep -v ^'USER' | sort -rn -k4 | head -15) 2>/dev/null
  print_code "${mem}"

  print_msg "### 父进程为1的进程信息"
  print_code "$(ps -e -o user,pid,ppid,cmd | awk '$3 == 1' | egrep -v "containerd-shim|/lib/systemd/systemd|/usr/sbin/cron|dbus|rsyslogd|containerd|/usr/sbin/sshd|/usr/bin/dockerd|/usr/sbin/arpd|/bin/login|/usr/sbin/vnstatd")"

  print_msg "### bash反弹shell进程"
  tcp_reverse=$(ps -ef | grep -P 'sh -i' | egrep -v 'grep' | awk '{print $2}' | xargs -i{} lsof -p {} | grep 'ESTAB')
  if [ -n $tcp_reverse ]; then
    print_code "$tcp_reverse"
  else
    print_code "未发现 bash -i 反弹shell！"
  fi
  print_msg "### SSH 软连接后门进程"
  if ps -ef | grep -P '\s+\-oport=\d+' >/dev/null 2>&1; then
    print_msg "$(ps -ef | grep -P '\s+\-oport=\d+')"
  else
    print_msg "未检测到SSH软连接后门"

  fi
}

network_check() {
  print_msg "## 网络/流量检查"
  #ifconfig
  print_msg '### ifconfig'
  print_code "$(/sbin/ifconfig -a)"

  #网络流量
  print_msg "### 网络流量"
  print_msg "**Interface**    **ByteRec**   **PackRec**   **ByteTran**   **PackTran**"
  awk ' NR>2' /proc/net/dev | while read line; do
    print_msg "$line" | awk -F ':' '{print "  "$1"  " $2}' | awk '{print $1"   "$2 "    "$3"   "$10"  "$11}'
  done

  #端口监听
  print_msg "### 端口监听"
  print_code "$(netstat -tulpen | grep -P 'tcp|udp.*')"

  #对外开放端口
  print_msg "### 对外开放端口"
  print_code "$(netstat -tulpen | awk '{print $1,$4}' | grep -P -o '.*0.0.0.0:(\d+)|:::\d+')"

  #网络连接
  print_msg "### 网络连接"
  print_msg "**TCP连接**"
  print_code "$(netstat -antop | grep -P ESTAB)"
  print_msg "**UDP连接**"
  print_code "$(netstat -anp | grep -P udp)"

  #连接状态
  print_msg "### TCP连接状态"
  print_code "$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')"

  #路由表
  print_msg "### 路由表"
  print_code "$(/sbin/route -nee)"

  #路由转发
  print_msg "### 路由转发"
  ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}')
  if [ -n "$ip_forward" ]; then
    print_code "/proc/sys/net/ipv4/ip_forward 已开启路由转发！"
  else
    print_code "该服务器未开启路由转发！"
  fi

  #DNS
  print_msg "### DNS Server"
  print_code "$(grep -oP '\d+\.\d+\.\d+\.\d+' </etc/resolv.conf)"

  #ARP
  print_msg "### ARP"
  print_code "$(arp -n -a)"

  #混杂模式
  print_msg "### 网卡混杂模式"
  if ip link | grep -P PROMISC >/dev/null 2>&1; then
    print_code "网卡存在混杂模式！"
  else
    print_code "网卡不存在混杂模式！"

  fi

  #防火墙
  print_msg "### IPTABLES防火墙"
  print_code "$(iptables -L)"

}

crontab_check() {
  print_msg "## 任务计划检查"

  #crontab
  print_msg "### Crontab 文件"
  print_msg "crontab -l"
  print_code "$(crontab -u root -l | egrep -v '#')"
  print_msg "ls -alht /etc/cron.*/*"
  print_code "$(ls -alht /etc/cron.*/*)"

  # crontab 内容
  print_msg "### Crontab 文件内容"
  print_code "$(find /var/spool/cron/ -type f -print0 | xargs -0 sudo cat | egrep -v '#')"

  #crontab可疑命令
  print_msg "### Crontab Backdoor"
  reverse_shell_check /etc/cron*
  reverse_shell_check /var/spool/cron/*
}

env_check() {
  print_msg "## 环境变量检查"
  #env
  print_msg "### env"
  print_code "$(env)"

  #PATH
  print_msg "### PATH"
  print_code "$PATH"

  print_msg "### Linux 动态链接库变量"

  #LD_PRELOAD
  if [[ -n $LD_PRELOAD ]]; then
    print_msg "**LD_PRELOAD**"
    print_code $LD_PRELOAD
  fi
  #LD_ELF_PRELOAD
  if [[ -n $LD_ELF_PRELOAD ]]; then
    print_msg "**LD_ELF_PRELOAD**"
    print_code $LD_ELF_PRELOAD
  fi
  #LD_AOUT_PRELOAD
  if [[ -n $LD_AOUT_PRELOAD ]]; then
    print_msg "**LD_AOUT_PRELOAD**"
    print_code $LD_AOUT_PRELOAD
  fi
  #PROMPT_COMMAND
  if [[ -n $PROMPT_COMMAND ]]; then
    print_msg "**PROMPT_COMMAND**"
    print_code $PROMPT_COMMAND
  fi
  #LD_LIBRARY_PATH
  if [[ -n $LD_LIBRARY_PATH ]]; then
    print_msg "**LD_LIBRARY_PATH**"
    print_code $LD_LIBRARY_PATH
  fi
  #ld.so.preload
  preload='/etc/ld.so.preload'
  if [ -e "${preload}" ]; then
    print_msg "**ld.so.preload**"
    print_code ${preload}
  fi
  # 正在运行的环境变量
  print_msg "### 正在运行的进程环境变量问题"
  print_code "$(grep -P 'LD_PRELOAD|LD_ELF_PRELOAD|LD_AOUT_PRELOAD|PROMPT_COMMAND|LD_LIBRARY_PATH' /proc/*/environ)"
}

user_check() {
  print_msg "## 用户信息检查"

  print_msg "### 可登陆用户"
  print_code "$(cat /etc/passwd | egrep -v 'nologin$|false$')"

  print_msg "### Root权限（非root）账号"
  print_code "$(cat /etc/passwd | awk -F ':' '$3==0' | egrep -v root:)"

  print_msg "### /etc/passwd文件修改日期: "

  print_code "$(stat /etc/passwd | grep -P -o '(?<=Modify: ).*')"

  print_msg "### sudoers(请注意NOPASSWD)"
  print_code "$(cat /etc/sudoers | egrep -v '#' | sed -e '/^$/d' | grep -P ALL)"

  print_msg "### 登录信息 w"
  print_code "$(w)"
  print_msg "### 登录信息 last"
  print_code "$(last)"
  print_msg "### 登录信息 lastlog"
  print_code "$(lastlog)"

  print_msg "### 登陆ip"
  print_code "$(grep -i -a Accepted /var/log/secure /var/log/auth.* 2>/dev/null | grep -Po '\d+\.\d+\.\d+\.\d+' | sort | uniq)"

}

init_check() {
  print_msg "## Linux启动项排查"

  print_msg "### /etc/init.d 记录"
  print_code "$(ls -alhtR /etc/init.d | head -n 30)"
  print_msg "### /etc/init.d 黑特征"
  reverse_shell_check /etc/init.d/*
}

service_check() {

  print_msg "## 服务状态检查"

  print_msg "### 正在运行的Service "
  print_code "$(systemctl -l | grep running | awk '{print $1}')"

  print_msg "### 最近添加的Service "
  print_code "$(ls -alhtR /etc/systemd/system/multi-user.target.wants)"
  print_code "$(ls -alht /etc/systemd/system/*.service | egrep -v 'dbus-org')"

}

bash_check() {

  print_msg -e "## Bash配置检查"
  #查看history文件
  print_msg "### History文件"
  print_code "$(ls -alht /root/.*_history)"

  print_msg "### History敏感操作"
  print_code "$(cat ~/.*history | grep -P '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])|http://|https://|\bssh\b|\bscp\b|\.tar|\bwget\b|\bcurl\b|\bnc\b|\btelnet\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b|/etc/passwd|/etc/shadow|/etc/hosts|\bnmap\b|\bfrp\b|\bnfs\b|\bsshd\b|\bmodprobe\b|\blsmod\b|\bsudo\b|mysql\b|mysqldump' | egrep -v 'man\b|ag\b|cat\b|sed\b|git\b|docker\b|rm\b|touch\b|mv\b|\bapt\b|\bapt-get\b')"

  #/etc/profile
  print_msg "### /etc/profile "
  print_code "$(cat /etc/profile | egrep -v '#')"

  # $HOME/.profile
  print_msg "### .profile "
  print_code "$(cat $HOME/.profile | egrep -v '#')"

  #/etc/rc.local
  print_msg "### /etc/rc.local "
  print_code "$(cat /etc/rc.local | egrep -v '#')"

  #~/.bash_profile
  print_msg "### ~/.bash_profile "
  if [ -e "$HOME/.bash_profile" ]; then
    print_code "$(cat ~/.bash_profile | egrep -v '#')"
  fi

  #~/.bashrc
  print_msg "### ~/.bashrc "
  print_code "$(cat ~/.bashrc | egrep -v '#' | sort | uniq)"

  #~/.bashrc
  print_msg "### ~/.zshrc "
  print_code "$(cat ~/.zshrc | egrep -v '#' | sort | uniq)"

}

file_check() {
  print_msg "## 文件检查"
  print_msg "系统文件修改时间 "
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
    print_msg "文件：$soft\t\t\t修改日期：$(stat $soft | grep -P -o '(?<=Modify: )[\d-\s:]+')"
  done

  print_msg "### ...隐藏文件"
  print_msg "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*.")"

  #tmp目录
  print_msg "### /tmp"
  print_code "$(ls /tmp /var/tmp /dev/shm -alht)"

  #alias 别名
  print_msg "### alias"
  print_code "$(alias | egrep -v 'git')"

  #SUID
  print_msg "### SUID"
  print_code "$(find / ! -path "/proc/*" -perm -004000 -type f | egrep -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps')"

  #lsof -L1 进程存在但文件已经没有了
  print_msg "### lsof +L1"
  print_code "$(lsof +L1)"

  #近7天改动
  print_msg "### 近七天文件改动 mtime "
  print_code "$(find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -mtime -7 -type f | egrep -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {})"

  #近7天改动
  print_msg "### 近七天文件改动 ctime "
  print_code "$(find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f | egrep -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {})"

  #大文件100mb
  #有些黑客会将数据库、网站打包成一个文件然后下载
  print_msg "### 大文件>200mb "
  print_code "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +200M -exec ls -alht {} + 2>/dev/null | grep -P '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' | egrep -v 'ib_logfile|ibd|mysql-bin|mysql-slow|ibdata1')"

  #敏感文件
  print_msg "### 敏感文件 "
  print_code "$(find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*tunnel\.(php|jsp|asp|py)|.*/nc\b|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc|.*aircrack|.*hydra|.*miner|.*/ew$' -type f | egrep -v '/lib/python' | xargs -i{} ls -alh {})"

  print_msg "### 可疑黑客文件 "
  print_code "$(find /root /home /opt /tmp /var/ /dev -regextype posix-extended -regex '.*wget|.*curl|.*openssl|.*mysql' -type f 2>/dev/null | xargs -i{} ls -alh {} | egrep -v '/pkgs/|/envs/|overlay2')"

}

rootkit_check() {
  print_msg "## Rootkit检查"
  #lsmod 可疑模块
  print_msg "### lsmod 可疑模块"
  print_code "$(lsmod | egrep -v 'ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|ip6table_raw|skx_edac|intel_rapl|wmi|acpi_pad|ast|i40e|ptp|nfit|libnvdimm|bpfilter|failover|toa|tls|nft_|qemu_fw_cfg')"

  print_msg "### Rootkit 内核模块"
  kernel=$(grep -E 'hide_tcp4_port|hidden_files|hide_tcp6_port|diamorphine|module_hide|module_hidden|is_invisible|hacked_getdents|hacked_kill|heroin|kernel_unlink|hide_module|find_sys_call_tbl|h4x_delete_module|h4x_getdents64|h4x_kill|h4x_tcp4_seq_show|new_getdents|old_getdents|should_hide_file_name|should_hide_task_name' </proc/kallsyms)
  if [ -n "$kernel" ]; then
    print_msg "存在内核敏感函数！疑似Rootkit内核模块"
    print_msg "$kernel"
  else
    print_msg "未找到内核敏感函数"
  fi

  print_msg "### 可疑的.ko模块"
  print_code "$(find / ! -path '/var/lib/docker/overlay2/*' ! -path '/proc/*' ! -path '/usr/lib/modules/*' ! -path '/lib/modules/*' ! -path '/boot/*' -regextype posix-extended -regex '.*\.ko' | egrep -v 'tutor.ko')"

}

ssh_check() {
  print_msg "## SSH检查"
  #SSH爆破IP
  print_msg "### SSH爆破"
  if [ $OS = 'Centos' ]; then
    print_code "$(grep -P -i -a 'authentication failure' /var/log/secure* | awk '{print $14}' | awk -F '=' '{print $2}' | grep -P '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25)"
  else
    print_code "$(grep -P -i -a 'authentication failure' /var/log/auth.* | awk '{print $14}' | awk -F '=' '{print $2}' | grep -P '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25)"
  fi

  #SSHD
  print_msg "### SSHD"
  print_msg "/usr/sbin/sshd"
  print_code "$(stat /usr/sbin/sshd | grep -P 'Access|Modify|Change')"

  #ssh后门配置检查
  print_msg "### SSH 后门配置"
  if [ -e "$HOME/.ssh/config" ]; then
    print_msg "$(grep LocalCommand <~/.ssh/config)"
    print_msg "$(grep ProxyCommand <~/.ssh/config)"
  else
    print_msg "未发现ssh配置文件"
  fi

  #PAM后门检查
  print_msg "### PAM 后门检测 "
  ls -la /usr/lib/security 2>/dev/null
  ls -la /usr/lib64/security 2>/dev/null

  print_msg "### SSH inetd后门检查 "
  if [ -e "/etc/inetd.conf" ]; then
    grep -E '(bash -i)' </etc/inetd.conf
  fi

  print_msg "### SSH key"
  user_dirs=$(ls /home)
  for user_dir in $user_dirs; do
    sshkey="/home/${user_dir}/.ssh/authorized_keys"

    if [ -s "${sshkey}" ]; then
      print_msg "User: ${user_dir}\n"
      print_code "$(cat ${sshkey})"
    fi
  done

  # 检查/root目录的authorized_keys文件
  print_msg "### authorized_keys"
  root_sshkey="/root/.ssh/authorized_keys"

  if [ -s "${root_sshkey}" ]; then
    print_code "$(cat ${root_sshkey})"
  else
    print_code "User: root - SSH key文件不存在"
  fi
}

webshell_check() {

  print_msg "## Webshell检查"

  print_msg "### PHP webshell查杀"
  print_code "$(grep -P -i -r -l 'array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\(' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l '\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input" $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l 'getruntime|processimpl|processbuilder|defineclass|classloader|naming.lookup|internaldofilter|elprocessor|scriptenginemanager|urlclassloader|versionhelper|registermapping|registerhandler|detecthandlermethods|\\u0063\\u006c\\u0061\\u0073\\u0073' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l 'phpinfo|move_uploaded_file|system|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func|ob_start' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l 'array_map|uasort|uksort|array_diff_uassoc|array_diff_ukey|array_intersect_uassoc|array_intersect_ukey|array_reduce|array_filter|array_udiff|array_udiff_assoc|array_udiff_uassoc|array_uintersect|array_uintersect_assoc|array_uintersect_uassoc|array_walk|array_walk_recursive|register_shutdown_function|register_tick_function|filter_var_array|yaml_parse|sqlite_create_function|fgetc|fgets|fgetss|fpassthru|fread|file_get_contents|readfile|stream_get_contents|stream_get_line|highlight_file|show_source|file_put_contents|pfsockopen|fsockopen' $webpath --include='*.php*' --include='*.phtml')"

  #JSP webshell查杀
  print_msg "### JSP webshell查杀"
  print_code "$(grep -P -i -r -l '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)' $webpath --include='*.jsp*' --include='*.jhtml')"

}

poison_check() {

  print_msg "## 供应链投毒检测"

  print_msg "### Python2 pip 检测"
  print_code "$(pip freeze | grep -P 'istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=|aioconsol')"

  print_msg "### Python3 pip 检测"
  print_code "$(pip3 freeze | grep -P 'istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=|aioconsol')"

}

miner_check() {

  print_msg "## 挖矿木马检查"

  print_msg "### 常规挖矿进程检测"
  print_code "$(ps aux | grep -P "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb|i2pd" | egrep -v 'grep')"
  print_code "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -regextype posix-extended -regex '.*systemctI|.*kworkerds|.*init10.cfg|.*wl.conf|.*crond64|.*watchbog|.*sustse|.*donate|.*proxkekman|.*cryptonight|.*sustes|.*xmrig|.*xmr-stak|.*suppoie|.*ririg|gg1.conf|.*cpuminer|.*xmr|.*xig|.*ddgs|.*minerd|.*hashvault|\.kthreadd|.*httpdz|.*kerbero|.*2t3ik|.*qW3xt|.*ztctb|.*miner.sh' -type f)"

  print_msg "### Ntpclient 挖矿木马检测"
  print_code "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/boot/*" -regextype posix-extended -regex 'ntpclient|Mozz')"
  print_code "$(ls -alh /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null)"

  print_msg "### WorkMiner 挖矿木马检测"
  print_code "$(ps aux | grep -P "work32|work64|/tmp/secure.sh|/tmp/auth.sh" | egrep -v 'grep')"
  print_code "$(ls -alh /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null)"

}

risk_check() {

  print_msg "## 服务器风险/漏洞检查"

  print_msg "### Redis弱密码检测"
  print_code "$(cat /etc/redis/redis.conf 2>/dev/null | grep -P '(?<=requirepass )(test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888)')"

  print_msg "### JDWP调试检测"
  if ps aux | grep -P '(?:runjdwp|agentlib:jdwp)' | egrep -v 'grep' >/dev/null 2>&1; then
    print_code "存在JDWP调试高风险进程\n $(ps aux | grep -P '(?:runjdwp|agentlib:jdwp)' | egrep -v 'grep') "
  fi

  print_msg "### Python http.server 列目录检测"
  print_code "$(ps aux | grep -P http.server | egrep -v 'grep')"
}

docker_check() {

  print_msg "## Docker信息检测"

  print_msg "### Docker运行的镜像"
  print_code "$(docker ps)"

  print_msg "### 检测CAP_SYS_ADMIN权限"
  if command -v capsh >/dev/null 2>&1; then
    cap_sys_adminNum=$(capsh --print | grep cap_sys_admin | wc -l)
    if [ $cap_sys_adminNum -gt 0 ]; then
      print_code "存在CAP_SYS_ADMIN权限！"
    fi
  else
    print_code "未发现capsh命令！"
  fi

  print_msg "### 检测CAP_DAC_READ_SEARCH权限"
  if command -v capsh >/dev/null 2>&1; then
    cap_dac_read_searchNum=$(capsh --print | grep cap_dac_read_search | wc -l)
    if [ $cap_dac_read_searchNum -gt 0 ]; then
      print_code "存在CAP_DAC_READ_SEARCH！"
    fi
  else
    print_code "未发现capsh命令！"
  fi
}

upload_report() {

  # 上传到指定接口
  if [[ -n $webhook_url ]]; then
    curl -X POST -F "file=@$filename" "$webhook_url"
  fi

}

# 服务器基础信息排查
base_check
# 进程信息排查（CPU/内存占用，后门进程排查）
process_check
# 网络排查
network_check
# 任务计划排查
crontab_check
# 环境变量排查
env_check
# 用户文件排查
user_check
# 启动项排查
init_check
# 服务排查
service_check
# bash 排查
bash_check
# 黑客/后门文件排查
file_check
# rootkit 排查
rootkit_check
# ssh 排查
ssh_check
# webshell 排查
webshell_check
# 供应链排查
poison_check
# 挖矿排查
miner_check
# 服务器风险检测
risk_check
# Docker 检测
docker_check
# upload_report
upload_report
