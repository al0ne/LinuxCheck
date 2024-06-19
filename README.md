# LinuxCheck

Linux应急处置/信息搜集/漏洞检测工具，支持基础配置/网络流量/任务计划/环境变量/用户信息/Services/bash/恶意文件/内核Rootkit/SSH/Webshell/挖矿文件/挖矿进程/供应链/服务器风险等13类70+项检查

## 更新

更新日志：2024年4月20日

- 调整输出为Markdown报告
- 弃用ag，还是使用Linux原生的grep命令，避免额外安装
- 优化代码格式，不在每条都要tee -a
- 更新Webshell检测逻辑
- 更新authorized_keys检测逻辑
- 服务器风险检查添加JDWP和Python HTTP Server检查
- 添加Docker 容器检测
- 添加PAM后门检测
- 添加本地报告上传能力，应对批量机器应急的情况。

更新日志：2022年08月05日

- 修复内核模块检查日志过多问题

更新日志：2022年03月07日

- 添加SSH软连接后门检测

更新日期：2021年10月17日

- 添加Ntpclient/WorkMiner/TeamTNT挖矿木马检测
- 添加Rootkit模块检测逻辑
- 添加Python pip投毒检测
- 添加$HOME/.profile查看
- 添加服务器风险检查(Redis)

## 功能

* 基础配置检查
    * 系统配置改动检查
    * 系统信息（IP地址/用户/开机时间/系统版本/Hostname/服务器SN）
    * CPU使用率
    * 登录用户信息
    * CPU TOP 15
    * 内存 TOP 15
    * 磁盘剩余空间检查
    * 硬盘挂载
    * 常用软件检查
    * /etc/hots
* 网络/流量检查
    * ifconfig
    * 网络流量
    * 端口监听
    * 对外开放端口
    * 网络连接
    * TCP连接状态
    * 路由表
    * 路由转发
    * DNS Server
    * ARP
    * 网卡混杂模式检查
    * iptables 防火墙
* 任务计划检查
    * 当前用户任务计划
    * /etc/系统任务计划
    * 任务计划文件创建时间
    * crontab 后门排查
* 环境变量检查
    * env
    * path
    * LD_PRELOAD
    * LD_ELF_PRELOAD
    * LD_AOUT_PRELOAD
    * PROMPT_COMMAND
    * LD_LIBRARY_PATH
    * ld.so.preload
* 用户信息检查
    * 可登陆用户
    * passwd文件修改日期
    * sudoers
    * 登录信息（w/last/lastlog）
    * 历史登陆ip
* Services 检查
    * SystemD运行服务
    * SystemD服务创建时间
* bash检查
    * History
    * History命令审计
    * /etc/profile
    * $HOME/.profile
    * /etc/rc.local
    * ~/.bash_profile
    * ~/.bashrc
    * bash反弹shell
* 文件检查
    * ...隐藏文件
    * 系统文件修改时间检测
    * 临时文件检查（/tmp /var/tmp /dev/shm）
    * alias
    * suid特殊权限检查
    * 进程存在文件未找到
    * 近七天文件改动 mtime
    * 近七天文件改动 ctime
    * 大文件>200mb
    * 敏感文件审计（nmap/sqlmap/ew/frp/nps等黑客常用工具）
    * 可疑黑客文件（黑客上传的wget/curl等程序，或者将恶意程序改成正常软件例如nps文件改为mysql）
* 内核Rootkit 检查
    * lsmod 可疑模块
    * 内核符号表检查
    * rootkit hunter 检查
    * rootkit .ko模块检查
* SSH检查
    * SSH 爆破
    * SSHD 检测
    * SSH 后门配置
    * SSH inetd后门检查
    * SSH key
* Webshell 检查
    * php webshell检查
    * jsp webshell检查
* 挖矿文件/进程检查
    * 挖矿文件检查
    * 挖矿进程检查
    * WorkMiner检测
    * Ntpclient检测
* 供应链投毒检查
    * Python PIP 投毒检查
* 服务器风险检查
    * Redis弱密码检测
    * JDWP 服务检测
    * Python http.server 检测
* Docker 权限检查

## Usage

第一种方式：通过git clone 安装

```bash
git clone https://github.com/al0ne/LinuxCheck.git
chmod u+x LinuxCheck.sh
./LinuxCheck.sh  
```
第二种方式：直接在线调用【在线调用就没办法使用报告上传的能力】

```
bash -c "$(curl -sSL https://raw.githubusercontent.com/al0ne/LinuxCheck/master/LinuxCheck.sh)"  
```

文件会保存成ipaddr_hostname_username_timestamp.log 这种格式

### 报告自动上传

如果是批量机器下发，脚本执行后会自动提交到某一个url下，将脚本里面的webhook_url 改成你自己的地址

```shell
# 报告上报的地址
webhook_url='http://localhost:5000/upload'

upload_report() {

  # 上传到指定接口
  if [[ -n $webhook_url ]]; then
    curl -X POST -F "file=@$filename" "$webhook_url"
  fi

}
```

在你的服务器上用Flask起一个服务，接收服务器上报的Markdown报告。

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    if file:
        filename = file.filename
        file.save(filename)
        return "File successfully uploaded", 200

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=9999)
```



## 参考

此工具的编写主要参考了以下几款工具/文章并结合个人经验完成

Linenum
https://github.com/lis912/Evaluation_tools  
https://ixyzero.com/blog/archives/4.html  
https://github.com/T0xst/linux   
https://github.com/grayddq/GScan  
