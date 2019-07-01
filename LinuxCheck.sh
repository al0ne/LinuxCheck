#!/bin/bash

echo ""
echo " ========================================================= "
echo " \                 Linux信息搜集脚本 V1.2                / "
echo " ========================================================= "
echo " # 支持Centos、Debian系统检测                    "
echo " # author：al0ne                    "
echo " # https://github.com/al0ne                    "
echo -e "\n"
if [ $UID -ne 0 ]; then
	echo "请使用root权限运行！！！"
	exit 1
fi
source /etc/os-release
if ag -V >/dev/null 2>&1; then
	echo -n
else
	case ${ID} in
	"debian" | "ubuntu" | "devuan")
		apt-get -y install silversearcher-ag >/dev/null 2>&1
		;;
	"centos" | "rhel fedora" | "rhel")
		yum -y install the_silver_searcher >/dev/null 2>&1
		;;
	*)
		exit 1
		;;
	esac

fi
#Centos安装net-tools
if ifconfig >/dev/null 2>&1; then
	echo -n
else
	case ${ID} in
	"centos" | "rhel fedora" | "rhel")
		yum -y install net-tools >/dev/null 2>&1
		;;
	*)
		exit 1
		;;
	esac

fi
#Centos安装lsof
if lsof >/dev/null 2>&1; then
	echo -n
else
	case ${ID} in
	"centos" | "rhel fedora" | "rhel")
		yum -y install lsof >/dev/null 2>&1
		;;
	*)
		exit 1
		;;
	esac

fi

# 设置保存文件
interface=$(cat /etc/network/interfaces|ag iface|ag -v 'lo|docker'|awk '{print $2}')
ipaddress=$(ifconfig $interface| ag -o '(?<=inet |inet addr:)\d+\.\d+\.\d+\.\d+' | ag -v '127.0.0.1')
filename=$ipaddress'_'`hostname`'_'`whoami`'_'`date +%s`'.log'

echo -e "\e[00;31m[+]系统改动\e[00m" | tee -a $filename
if debsums --help >/dev/null 2>&1; then
	debsums -e | ag -v 'OK'| tee -a $filename
else
	case ${ID} in
	"debian" | "ubuntu" | "devuan")
		apt install -y debsums >/dev/null 2>&1
		debsums -e | ag -v 'OK' | tee -a $filename
		;;
	"centos" | "rhel fedora" | "rhel")
		rpm -Va | tee -a $filename
		;;
	*)
		exit 1
		;;
	esac
fi
echo -e "\n" | tee -a $filename
echo -e "\e[00;31m[+]系统信息\e[00m" | tee -a $filename
#当前用户
echo -e "USER:\t\t" $(whoami) 2>/dev/null | tee -a $filename
#版本信息
echo -e "OS Version:\t" ${PRETTY_NAME} | tee -a $filename
#主机名
echo -e "Hostname: \t" $(hostname -s) | tee -a $filename
#uptime
echo -e "uptime: \t" $(uptime | awk -F ',' '{print $1}') | tee -a $filename
#cpu信息
echo -e "CPU info:\t" $(cat /proc/cpuinfo | ag -o '(?<=model name\t: ).*' | head -n 1) | tee -a $filename
# ipaddress
ipaddress=$(ifconfig | ag -o '(?<=inet |inet addr:)\d+\.\d+\.\d+\.\d+' | ag -v '127.0.0.1') >/dev/null 2>&1
echo -e "IPADDR:\t\t${ipaddress}" | sed ":a;N;s/\n/ /g;ta" | tee -a $filename
echo -e "\n" | tee -a $filename

echo -e "\e[00;31m[+]CPU使用率:  \e[00m" | tee -a $filename
awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null | while read line; do
	echo "$line" | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
        print$1" Free "free/total*100"%",\
        "Used " (total-free)/total*100"%"}' | tee -a $filename
done
echo -e "\n" | tee -a $filename
#CPU占用TOP 10
cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -10) 2>/dev/null
echo -e "\e[00;31m[+]CPU TOP10:  \e[00m\n${cpu}\n" | tee -a $filename
#内存占用TOP 10
cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -10) 2>/dev/null
echo -e "\e[00;31m[+]内存占用 TOP10:  \e[00m\n${cpu}\n" | tee -a $filename
#内存占用
echo -e "\e[00;31m[+]内存占用\e[00m" | tee -a $filename
free -mh | tee -a $filename
echo -e "\n" | tee -a $filename
#剩余空间
echo -e "\e[00;31m[+]剩余空间\e[00m" | tee -a $filename
df -mh | tee -a $filename
echo -e "\n" | tee -a $filename
echo -e "\e[00;31m[+]硬盘挂载\e[00m" | tee -a $filename
cat /etc/fstab | ag -v "#" | awk '{print $1,$2,$3}' | tee -a $filename
echo -e "\n" | tee -a $filename
#ifconfig
echo -e "\e[00;31m[+]ifconfig\e[00m" | tee -a $filename
/sbin/ifconfig -a | tee -a $filename
echo -e "\n" | tee -a $filename
#网络流量
echo -e "\e[00;31m[+]网络流量 \e[00m" | tee -a $filename
echo "Interface    ByteRec   PackRec   ByteTran   PackTran" | tee -a $filename
awk ' NR>2' /proc/net/dev | while read line; do
	echo "$line" | awk -F ':' '{print "  "$1"  " $2}' | \
	awk '{print $1"   "$2 "    "$3"   "$10"  "$11}' | tee -a $filename
done
echo -e "\n" | tee -a $filename
#端口监听
echo -e "\e[00;31m[+]端口监听\e[00m" | tee -a $filename
netstat -tulpen | ag 'tcp|udp.*' --nocolor | tee -a $filename
echo -e "\n" | tee -a $filename
#对外开放端口
echo -e "\e[00;31m[+]对外开放端口\e[00m" | tee -a $filename
netstat -tulpen | awk '{print $1,$4}' | ag -o '.*0.0.0.0:(\d+)' --nocolor | tee -a $filename
echo -e "\n" | tee -a $filename
#网络连接
echo -e "\e[00;31m[+]网络连接\e[00m" | tee -a $filename
netstat -antop | ag ESTAB --nocolor | tee -a $filename
echo -e "\n" | tee -a $filename
#连接状态
echo -e "\e[00;31m[+]TCP连接状态\e[00m" | tee -a $filename
netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}' | tee -a $filename
echo -e "\n" | tee -a $filename
#路由表
echo -e "\e[00;31m[+]路由表\e[00m" | tee -a $filename
/sbin/route -nee | tee -a $filename
echo -e "\n" | tee -a $filename
#DNS
echo -e "\e[00;31m[+]DNS Server\e[00m" | tee -a $filename
cat /etc/resolv.conf | ag -o '\d+\.\d+\.\d+\.\d+' --nocolor | tee -a $filename
echo -e "\n" | tee -a $filename
#混杂模式
echo -e "\e[00;31m[+]网卡混杂模式\e[00m" | tee -a $filename
if ip link | ag PROMISC >/dev/null 2>&1; then
	echo "网卡存在混杂模式！" | tee -a $filename
else
	echo "网卡不存在混杂模式" | tee -a $filename

fi
echo -e "\n" | tee -a $filename
#安装软件
echo -e "\e[00;31m[+]常用软件\e[00m" | tee -a $filename
cmdline=(
	"which perl"
	"which gcc"
	"which g++"
	"which python"
	"which php"
	"which cc"
	"which go"
	"which node"
	"which clang"
	"which ruby"
	"which curl"
	"which wget"
	"which mysql"
	"which redis"
	"which apache"
	"which nginx"
	"which git"
	"which mongodb"
	"which docker"
	"which tftp"
	"which psql"
)

for prog in "${cmdline[@]}"; do
	soft=$($prog)
	if [ "$soft" ] 2>/dev/null; then
		echo -e "$soft" | ag -o '\w+$' --nocolor | tee -a $filename
	fi
done
echo -e "\n" | tee -a $filename
#crontab
echo -e "\e[00;31m[+]Crontab\e[00m" | tee -a $filename
crontab -u root -l | ag -v '#' --nocolor | tee -a $filename
ls -al /etc/cron.*/* | tee -a $filename
echo -e "\n" | tee -a $filename
#env
echo -e "\e[00;31m[+]env\e[00m" | tee -a $filename
env | tee -a $filename
echo -e "\n" | tee -a $filename
#LD_PRELOAD
echo -e "\e[00;31m[+]LD_PRELOAD\e[00m" | tee -a $filename
echo ${LD_PRELOAD} | tee -a $filename
echo -e "\n" | tee -a $filename
#passwd信息
echo -e "\e[00;31m[+]可登陆用户\e[00m" | tee -a $filename
cat /etc/passwd | ag -v 'nologin$|false$' | tee -a $filename
echo -e "passwd文件修改日期:" $(stat /etc/passwd | ag -o '(?<=Modify: ).*' --nocolor) | tee -a $filename
echo -e "\n" | tee -a $filename
echo -e "\e[00;31m[+]sudoers(请注意NOPASSWD)\e[00m" | tee -a $filename
cat /etc/sudoers | ag -v '#' | sed -e '/^$/d' | ag ALL --nocolor | tee -a $filename
echo -e "\n" | tee -a $filename
#防火墙
echo -e "\e[00;31m[+]IPTABLES防火墙\e[00m" | tee -a $filename
iptables -L | tee -a $filename
echo -e "\n" | tee -a $filename
#登陆信息
echo -e "\e[00;31m[+]登录信息\e[00m" | tee -a $filename
w | tee -a $filename
echo -e "\n" | tee -a $filename
last | tee -a $filename
echo -e "\n" | tee -a $filename
lastlog | tee -a $filename
echo "登陆ip:" $(ag -a accepted /var/log/secure /var/log/auth.* 2>/dev/null | ag -o '\d+\.\d+\.\d+\.\d+' | sort | uniq) | tee -a $filename
echo -e "\n" | tee -a $filename
#运行服务
echo -e "\e[00;31m[+]Service \e[00m" | tee -a $filename
case ${ID} in
"debian" | "ubuntu" | "devuan")
	service --status-all | ag -Q '+' --nocolor | tee -a $filename
	;;
"centos" | "rhel fedora" | "rhel")
	service --status-all | ag -Q 'is running' --nocolor | tee -a $filename
	;;
*)
	exit 1
	;;
esac
echo -e "\n" | tee -a $filename
#查看history文件
echo -e "\e[00;31m[+]History\e[00m" | tee -a $filename
ls -la ~/.*_history | tee -a $filename
ls -la /root/.*_history | tee -a $filename
echo -e "\n" | tee -a $filename
cat ~/.*history | ag '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])|http://|https://|ssh|scp|tar' --nocolor | tee -a $filename
echo -e "\n" | tee -a $filename
#HOSTS
echo -e "\e[00;31m[+]/etc/hosts \e[00m" | tee -a $filename
cat /etc/hosts | ag -v "#" | tee -a $filename
echo -e "\n" | tee -a $filename
#/etc/profile
echo -e "\e[00;31m[+]/etc/profile \e[00m" | tee -a $filename
cat /etc/profile | ag -v '#' | tee -a $filename
echo -e "\n" | tee -a $filename
#/etc/rc.local
echo -e "\e[00;31m[+]/etc/rc.local \e[00m" | tee -a $filename
cat /etc/rc.local | ag -v '#' | tee -a $filename
echo -e "\n" | tee -a $filename
#~/.bash_profile
echo -e "\e[00;31m[+]~/.bash_profile \e[00m" | tee -a $filename
cat ~/.bash_profile | ag -v '#' | tee -a $filename
echo -e "\n" | tee -a $filename
#~/.bashrc
echo -e "\e[00;31m[+]~/.bashrc \e[00m" | tee -a $filename
cat ~/.bashrc | ag -v '#' | tee -a $filename
echo -e "\n" | tee -a $filename
#bash反弹shell
echo -e "\e[00;31m[+]bash反弹shell \e[00m" | tee -a $filename
ps -ef | ag 'bash -i' | ag -v 'ag' | awk '{print $2}' | xargs -i{} lsof -p {} | ag 'ESTAB' --nocolor | tee -a $filename
echo -e "\n" | tee -a $filename
#...隐藏文件
echo -e "\e[00;31m[+]...隐藏文件 \e[00m" | tee -a $filename
find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*." | tee -a $filename
echo -e "\n" | tee -a $filename
#tmp目录
echo -e "\e[00;31m[+]/tmp \e[00m" | tee -a $filename
ls /tmp /var/tmp /dev/shm -alh | tee -a $filename
echo -e "\n" | tee -a $filename
#alias 别名
echo -e "\e[00;31m[+]alias \e[00m" | tee -a $filename
alias|ag -v 'git' | tee -a $filename
echo -e "\n" | tee -a $filename
#SUID
echo -e "\e[00;31m[+]SUID \e[00m" | tee -a $filename
find / ! -path "/proc/*" -perm -004000 -type f | ag -v 'snap|docker' | tee -a $filename
echo -e "\n" | tee -a $filename
#lsof -L1
echo -e "\e[00;31m[+]lsof -L1 \e[00m" | tee -a $filename
lsof +L1 | tee -a $filename
echo -e "\n" | tee -a $filename
#近7天改动
echo -e "\e[00;31m[+]近七天文件改动 \e[00m" | tee -a $filename
find /etc /bin /sbin /dev /root/ /home /tmp -mtime -7 -type f | ag -v 'cache|vim|/share/|/lib/|.zsh|.gem' | xargs -i{} ls -alh {} | tee -a $filename
echo -e "\n" | tee -a $filename
#大文件100mb
echo -e "\e[00;31m[+]大文件>100mb \e[00m" | tee -a $filename
find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +100M -print 2>/dev/null | xargs -i{} ls -alh {} | ag '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' --nocolor  | tee -a $filename
echo -e "\n" | tee -a $filename
#敏感文件
echo -e "\e[00;31m[+]敏感文件 \e[00m" | tee -a $filename
find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*backdoor|.*tunnel\.(php|jsp|asp|py)|.*\bnc|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc' | tee -a $filename
echo -e "\n" | tee -a $filename
#lsmod 可疑模块
echo -e "\e[00;31m[+]lsmod 可疑模块\e[00m" | tee -a $filename
sudo lsmod |ag -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4" | tee -a $filename
echo -e "\n" | tee -a $filename
#检查ssh key
echo -e "\e[00;31m[+]SSH key\e[00m" | tee -a $filename
sshkey=${HOME}/.ssh/authorized_keys
if [ -e "${sshkey}" ]; then
	cat ${sshkey} | tee -a $filename
else
	echo -e "SSH key文件不存在\n" | tee -a $filename
fi
echo -e "\n" | tee -a $filename
#PHP webshell查杀
echo -e "\e[00;31m[+]PHP webshell查杀\e[00m" | tee -a $filename
ag --php -l -s 'assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|\(\$\$\w+|call_user_func\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\(' / | tee -a $filename
echo -e "\n" | tee -a $filename
rkhuntercheck() {
	if rkhunter >/dev/null 2>&1; then
		rkhunter --checkall --sk | ag -v 'OK|Not found|None found'
	else
		wget 'https://astuteinternet.dl.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz' -O /tmp/rkhunter.tar.gz >/dev/null 2>&1
		tar -zxvf /tmp/rkhunter.tar.gz -C /tmp >/dev/null 2>&1
		cd /tmp/rkhunter-1.4.6/
		./installer.sh --install >/dev/null 2>&1
		rkhunter --checkall --sk | ag -v 'OK|Not found|None found'

	fi
}
ping -c 1 114.114.114.114 >/dev/null 2>&1
if [ $? -eq 0 ]; then
	echo -e "\e[00;31m[+]RKhunter\e[00m" | tee -a $filename
	rkhuntercheck | tee -a $filename
else
	echo -e '\n' | tee -a $filename
fi
