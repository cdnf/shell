#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	Author: 金将军
#=================================================

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)
config_ymlfile="/etc/XrayR/config.yml"
config_rulefile="/etc/XrayR/rulelist"
config_dnsfile="/etc/XrayR/dns.json"

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用root用户运行此脚本！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    echo -e "${red}未检测到系统版本，本程序只支持CentOS，Ubuntu和Debian！，如果检测有误，请联系作者${plain}\n" && exit 1
fi

if [ "$(getconf WORD_BIT)" != '32' ] && [ "$(getconf LONG_BIT)" != '64' ] ; then
    echo "本软件不支持 32 位系统(x86)，请使用 64 位系统(x86_64)，如果检测有误，请联系作者"
    exit 2
fi

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}请使用 CentOS 7 或更高版本的系统！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}请使用 Ubuntu 16 或更高版本的系统！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}请使用 Debian 8 或更高版本的系统！${plain}\n" && exit 1
    fi
fi
install_base(){
    if [[ x"${release}" == x"centos" ]]; then
        yum install epel-release -y
        yum install wget curl unzip gzip tar crontabs socat jq -y
    else
        apt install wget curl unzip gzip tar cron socat jq -y
    fi
}
# 实现按任意键继续
get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}
pause_press(){
	# 启用功能的开关 1开启|其它不开启
	enable_pause=1

	# 判断第一个参数是否为空，约定俗成的写法
	if [ "x$1" != "x" ]; then
		echo $1
	fi
	if [ $enable_pause -eq 1 ]; then
		# echo "Press any key to continue!"
		echo "按任意键继续!"
		char=`get_char`
	fi
}

# Writing json
# 配置文件说明：https://crackair.gitbook.io/xrayr-project/xrayr-pei-zhi-wen-jian-shuo-ming/config
config_base(){
    cat >${config_ymlfile} <<EOF
Log:
    Level: error # Log level: none, error, warning, info, debug 
    AccessPath: # ./access.Log
    ErrorPath: # ./error.log
DnsConfigPath: # ./dns.json Path to dns config, check https://xtls.github.io/config/base/dns/ for help
RouteConfigPath: # ./route.json # Path to route config, check https://xtls.github.io/config/base/route/ for help
OutboundConfigPath: # ./custom_outbound.json # Path to custom outbound config, check https://xtls.github.io/config/base/outbound/ for help
ConnetionConfig:
    Handshake: 4 # Handshake time limit, Second
    ConnIdle: 10 # Connection idle time limit, Second
    UplinkOnly: 2 # Time limit when the connection downstream is closed, Second
    DownlinkOnly: 4 # Time limit when the connection is closed after the uplink is closed, Second
    BufferSize: 64 # The internal cache size of each connection, kB
Nodes:
EOF
    echo -e "基础配置已写入 ${green}${config_ymlfile}${plain}"
}
config_nodes(){
    if [[ -f ${config_ymlfile} ]]; then
        cat >>${config_ymlfile} <<EOF
    -
        PanelType: "Panel_Type" # Panel type: SSpanel, V2board, PMpanel, Proxypanel
        ApiConfig:
            ApiHost: "Api_Host"
            ApiKey: "Api_Key"
            NodeID: "Node_ID"
            NodeType: "Node_Type" # Node type: V2ray, Trojan, Shadowsocks, Shadowsocks-Plugin
            Timeout: 30 # Timeout for the api request
            EnableVless: Enable_Vless # Enable Vless for V2ray Type
            EnableXTLS: Enable_XTLS # Enable XTLS for V2ray and Trojan
            SpeedLimit: 0 # Mbps, Local settings will replace remote settings, 0 means disable
            DeviceLimit: 0 # Local settings will replace remote settings, 0 means disable
            RuleListPath: "Rule_List" # ./rulelist Path to local rulelist file
        ControllerConfig:
            ListenIP: 0.0.0.0 # IP address you want to listen
            SendIP: 0.0.0.0 # IP address you want to send pacakage
            UpdatePeriodic: 60 # Time to update the nodeinfo, how many sec.
            EnableDNS: false # Use custom DNS config, Please ensure that you set the dns.json well
            DNSType: AsIs # AsIs, UseIP, UseIPv4, UseIPv6, DNS strategy
            EnableProxyProtocol: false # Only works for WebSocket and TCP
            EnableFallback: false # Only support for Trojan and Vless
            FallBackConfigs:  # Support multiple fallbacks
                -
                    SNI: # TLS SNI(Server Name Indication), Empty for any
                    Path: # HTTP PATH, Empty for any
                    Dest: 80 # Required, Destination of fallback, check https://xtls.github.io/config/fallback/ for details.
                    ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for dsable
            CertConfig:
                CertMode: "Cert_Mode" # Option about how to get certificate: none, file, http, dns. Choose "none" will forcedly disable the tls config.
                CertDomain: "Cert_Domain" # Domain to cert
                CertFile: "./cert/Cert_Domain.cert" # Provided if the CertMode is file
                KeyFile: "./cert/Cert_Domain.key" # http filepath is /etc/XrayR/cert/certificates/
                Email: "Cert_Email"
EOF
        echo -e "节点配置已写入 ${green}${config_ymlfile}${plain}"
    else
        echo "配置文件不存在，请先安装XrayR"
        exit 1
    fi
}
Cert_Provider_alidns(){
    cat >>${config_ymlfile} <<EOF
                Provider: "alidns" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    ALICLOUD_ACCESS_KEY: "ACCESS_KEY"
                    ALICLOUD_SECRET_KEY: "SECRET_KEY"
EOF
}
Cert_Provider_dnspod(){
    cat >>${config_ymlfile} <<EOF
                Provider: "dnspod" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    DNSPOD_API_KEY: "ACCESS_KEY"
EOF
}
Cert_Provider_cloudflare(){
    cat >>${config_ymlfile} <<EOF
                Provider: "cloudflare" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    # CF_API_KEY: "ACCESS_KEY"
                    CF_DNS_API_TOKEN: "SECRET_KEY"
EOF
}
Cert_Provider_namesilo(){
    cat >>${config_ymlfile} <<EOF
                Provider: "namesilo" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    NAMESILO_API_KEY: "ACCESS_KEY"
EOF
}
config_dns(){
    cat >${config_dnsfile} <<EOF
{
    "servers": [
        "1.1.1.1",
        "8.8.8.8",
        "localhost"
    ],
    "tag": "dns_inbound"
}
EOF
}
# 生成随机gmail邮箱
config_Email(){
    local Cert_Email_Account=$(((RANDOM << 9)))
    Cert_Email=${Cert_Email_Account}@gmail.com
}
# 优先取出已存在的邮箱账号
config_Email_exist(){
    Cert_Email_Account=$(ls /etc/XrayR/cert/accounts/acme-v02.api.letsencrypt.org)
    if [[ -n ${Cert_Email_Account} ]]; then
        Cert_Email=${Cert_Email_Account}
    else
        config_Email
    fi
}
# 生成本地审计规则rulelist
config_audit(){
    cat >${config_rulefile} <<EOF
(api|ps|sv|offnavi|newvector|ulog\.imap|newloc)(\.map|)\.(baidu|n\.shifen)\.com
(.*\.||)(360|so|qq|163|sohu|sogoucdn|sogou|uc|58|taobao|qpic)\.(org|com|net|cn)
(.*\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\.(org|com|net)
(.*\.||)(shenzhoufilm|secretchina|renminbao|aboluowang|mhradio|guangming|zhengwunet|soundofhope|yuanming|zhuichaguoji|fgmtv|xinsheng|shenyunperformingarts|epochweekly|tuidang|shenyun|falundata|bannedbook)\.(org|com|net)
(.*\.||)(icbc|ccb|boc|bankcomm|abchina|cmbchina|psbc|cebbank|cmbc|pingan|spdb|citicbank|cib|hxb|bankofbeijing|hsbank|tccb|4001961200|bosc|hkbchina|njcb|nbcb|lj-bank|bjrcb|jsbchina|gzcb|cqcbank|czbank|hzbank|srcb|cbhb|cqrcb|grcbank|qdccb|bocd|hrbcb|jlbank|bankofdl|qlbchina|dongguanbank|cscb|hebbank|drcbank|zzbank|bsb|xmccb|hljrcc|jxnxs|gsrcu|fjnx|sxnxs|gx966888|gx966888|zj96596|hnnxs|ahrcu|shanxinj|hainanbank|scrcu|gdrcu|hbxh|ynrcc|lnrcc|nmgnxs|hebnx|jlnls|js96008|hnnx|sdnxs)\.(org|com|net|cn)
(.*\.||)(firstbank|bot|cotabank|megabank|tcb-bank|landbank|hncb|bankchb|tbb|ktb|tcbbank|scsb|bop|sunnybank|kgibank|fubon|ctbcbank|cathaybk|eximbank|bok|ubot|feib|yuantabank|sinopac|esunbank|taishinbank|jihsunbank|entiebank|hwataibank|csc|skbank)\.(org|com|net|tw)
(.*\.||)(unionpay|alipay|baifubao|yeepay|99bill|95516|51credit|cmpay|tenpay|lakala|jdpay)\.(org|com|net|cn)
(.*\.||)(metatrader4|metatrader5|mql5)\.(org|com|net)
EOF
}
# Pre-installation settings
config_set(){
    read -p "前端节点信息里面的节点ID:" Node_ID
        [ -z "${Node_ID}" ] && Node_ID=1
    read -p "前端面板认证域名(包括http[s]://):" Api_Host
        [ -z "${Api_Host}" ] && Api_Host="http://1.1.1.1"
    read -p "前端面板的apikey:" Api_Key
        [ -z "${Api_Key}" ] && Api_Key="abc123"
    echo -e "[1] SSpanel \t [2] V2board"
    read -p "前端面板类型（默认V2board）:" panel_num
        [ -z "${panel_num}" ] && panel_num="2"
    if [ "$panel_num" == "1" ]; then
        Panel_Type="SSpanel"
    elif [ "$panel_num" == "2" ]; then
        Panel_Type="V2board"
    else
        echo "type error, please try again"
        exit
    fi
    echo -e "[1] V2ray \t [2] Trojan \t [3] Shadowsocks"
    read -p "节点类型（默认V2ray）:" node_num
        [ -z "${node_num}" ] && node_num="1"
    if [ "$node_num" == "1" ]; then
        Node_Type="V2ray"
    elif [ "$node_num" == "2" ]; then
        Node_Type="Trojan"
    elif [ "$node_num" == "3" ]; then
        Node_Type="Shadowsocks"
    else
        echo "type error, please try again"
        exit
    fi
    if [ "$node_num" == "1" -o "$node_num" == "2" ]; then
        echo -e "[1] 是 \t [2] 否"
        read -p "是否开启tls（默认否）:" is_tls
        if [ "$is_tls" == "1" ]; then
            read -p "请输入解析到本机的域名:" Cert_Domain
            echo -e "[1] 是 \t [2] 否"
            read -p "是否开启xtls（默认否）:" is_xtls
            if [ "$node_num" == "1" ]; then
                echo -e "[1] 是 \t [2] 否"
                read -p "是否开启vless（默认否）:" is_vless
            fi
            echo -e "[1] http \t [2] file \t [3] dns"
            read -p "证书认证模式（默认http）:" Cert_Mode_num
                [ -z "${Cert_Mode_num}" ] && Cert_Mode_num="1"
            if  [[ "${Cert_Mode_num}" == "2" ]]; then
                Cert_Mode="file"
            elif [[ "${Cert_Mode_num}" == "3" ]]; then
                Cert_Mode="dns"
                echo -e "[1] alidns \t [2] dnspod \t [3] cloudflare \t [4] namesilo"
                read -p "DNS托管商:" Cert_Provider_num
                    if [[ "${Cert_Provider_num}" == "1" ]]; then
                        Cert_Provider="alidns"
                        echo -e "请输入 ALICLOUD_ACCESS_KEY"
                        read -p "ALICLOUD_ACCESS_KEY:" ACCESS_KEY
                        echo -e "请输入 ALICLOUD_SECRET_KEY"
                        read -p "ALICLOUD_SECRET_KEY:" SECRET_KEY
                    elif [[ "${Cert_Provider_num}" == "2" ]]; then
                        Cert_Provider="dnspod"
                        echo -e "请输入 DNSPOD_API_KEY"
                        read -p "DNSPOD_API_KEY:" ACCESS_KEY
                    elif [[ "${Cert_Provider_num}" == "3" ]]; then
                        Cert_Provider="cloudflare"
                        # echo -e "请输入 CF_API_KEY"
                        # read -p "CF_API_KEY:" ACCESS_KEY
                        echo -e "请输入 CF_DNS_API_TOKEN"
                        read -p "CF_DNS_API_TOKEN:" SECRET_KEY
                    elif [[ "${Cert_Provider_num}" == "4" ]]; then
                        Cert_Provider="namesilo"
                        echo -e "请输入 NAMESILO_API_KEY"
                        read -p "NAMESILO_API_KEY:" ACCESS_KEY
                    else
                        Cert_Provider="cloudflare"
                        echo -e "未正确选择DNS托管商...默认使用 cloudflare"
                        # echo -e "请输入 CF_API_KEY"
                        # read -p "CF_API_KEY:" ACCESS_KEY
                        echo -e "请输入 CF_DNS_API_TOKEN"
                        read -p "CF_DNS_API_TOKEN:" SECRET_KEY
                    fi
            else
                Cert_Mode="http"
            fi
        fi
    fi
}
config_modify(){
    sed -i "s|Panel_Type|${Panel_Type}|" ${config_ymlfile}
    sed -i "s|Api_Host|${Api_Host}|" ${config_ymlfile}
    sed -i "s|Api_Key|${Api_Key}|" ${config_ymlfile}
    sed -i "s|Node_ID|${Node_ID}|" ${config_ymlfile}
    sed -i "s|Node_Type|${Node_Type}|" ${config_ymlfile}
    sed -i "s|Cert_Domain|${Cert_Domain}|" ${config_ymlfile}
    if [ "$is_tls" == "1" ]; then
        sed -i "s|Cert_Mode|${Cert_Mode}|" ${config_ymlfile}
        install_acme
    else
        sed -i "s|Cert_Mode|none|" ${config_ymlfile}
    fi
    if [ "$is_xtls" == "1" ]; then
        sed -i "s|Enable_XTLS|true|" ${config_ymlfile}
    else
        sed -i "s|Enable_XTLS|false|" ${config_ymlfile}
    fi
    if [ "$is_vless" == "1" ]; then
        sed -i "s|Enable_Vless|true|" ${config_ymlfile}
    else
        sed -i "s|Enable_Vless|false|" ${config_ymlfile}
    fi
    # 邮箱账号
    config_Email_exist
    sed -i "s|Cert_Email|${Cert_Email}|" ${config_ymlfile}

    if [[ "${Cert_Provider}" == "alidns" ]]; then
        Cert_Provider_alidns
        sed -i "s|\"ACCESS_KEY\"|${ACCESS_KEY}|" ${config_ymlfile}
        sed -i "s|\"SECRET_KEY\"|${SECRET_KEY}|" ${config_ymlfile}
    elif [[ "${Cert_Provider}" == "dnspod" ]]; then
        Cert_Provider_dnspod
        sed -i "s|\"ACCESS_KEY\"|${ACCESS_KEY}|" ${config_ymlfile}
    elif [[ "${Cert_Provider}" == "namesilo" ]]; then
        Cert_Provider_namesilo
        sed -i "s|\"ACCESS_KEY\"|${ACCESS_KEY}|" ${config_ymlfile}
    elif [[ "${Cert_Provider}" == "cloudflare" ]]; then
        Cert_Provider_cloudflare
        # sed -i "s|\"ACCESS_KEY\"|${ACCESS_KEY}|" ${config_ymlfile}
        sed -i "s|\"SECRET_KEY\"|${SECRET_KEY}|" ${config_ymlfile}
    else
        echo -e "未启用或未正确选择dns认证，跳过……"
        echo -e "如不符合预期请自行检查 ${red}${config_ymlfile}${plain}"
    fi
    # V2board启用本地审计
    if [ "${Panel_Type}"=="V2board"]; then
        echo -e "V2board不支持在线同步规则，将启用本地规则……"
        if [ "${Node_Type}" == "Trojan" -o "${Node_Type}" == "Shadowsocks" ]; then
            config_audit
            sed -i "s|\"Rule_List\"|\"${config_rulefile}\"|" ${config_ymlfile}
        fi
    else
        sed -i "s|\"Rule_List\"||" ${config_ymlfile}
    fi
}

# 0: running, 1: not running, 2: not installed
check_status(){
    if [[ ! -f /etc/systemd/system/XrayR.service ]]; then
        return 2
    fi
    temp=$(systemctl status XrayR | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

install_acme(){
    install_base
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        echo -e "${green}开始安装 acme${plain}"
        curl https://get.acme.sh | sh
    else
        echo -e "acme已经在系统里了..."
    fi
}

install_XrayR(){
    install_base
    echo -e "${green}开始安装 XrayR${plain}"
    if [[ -e /usr/local/XrayR/ ]]; then
        rm -rf /usr/local/XrayR/
    fi

    mkdir -p /usr/local/XrayR/
	cd /usr/local/XrayR/

    if  [[ $# == 0 ]] ;then
        last_version=$(curl -Ls "https://api.github.com/repos/XrayR-project/XrayR/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}检测 XrayR 版本失败，可能是超出 Github API 限制，请稍后再试，或手动指定 XrayR 版本安装${plain}"
            exit 1
        fi
        echo -e "检测到 XrayR 最新版本：${last_version}，开始安装"
        wget -N --no-check-certificate -O /usr/local/XrayR/XrayR-linux-64.zip https://github.com/XrayR-project/XrayR/releases/download/${last_version}/XrayR-linux-64.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 XrayR 失败，请确保你的服务器能够下载 Github 的文件${plain}"
            exit 1
        fi
    else
        last_version=$1
        url="https://github.com/XrayR-project/XrayR/releases/download/${last_version}/XrayR-linux-64.zip"
        echo -e "开始安装 XrayR v$1"
        wget -N --no-check-certificate -O /usr/local/XrayR/XrayR-linux-64.zip ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 XrayR v$1 失败，请确保此版本存在${plain}"
            exit 1
        fi
    fi

    unzip XrayR-linux-64.zip
    rm -f XrayR-linux-64.zip
    chmod +x XrayR
    rm -f /etc/systemd/system/XrayR.service
    file="https://github.com/XrayR-project/XrayR-release/raw/master/XrayR.service"
    wget -N --no-check-certificate -O /etc/systemd/system/XrayR.service ${file}
    #cp -f XrayR.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl stop XrayR
    systemctl enable XrayR
    echo -e "${green}XrayR ${last_version}${plain} 安装完成，已设置开机自启"
    mkdir -p /etc/XrayR/
    cp geoip.dat /etc/XrayR/
    cp geosite.dat /etc/XrayR/ 

    if [[ ! -f /etc/XrayR/dns.json ]]; then
        config_dns
    fi

    if [[ ! -f ${config_ymlfile} ]]; then
        config_base && config_nodes
        config_set && config_modify
        echo -e ""
        echo -e "全新安装完成，更多内容请见：https://github.com/XrayR-project/XrayR"
    else
        systemctl start XrayR
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}XrayR 重启成功${plain}"
        else
            echo -e "${red}XrayR 可能启动失败，请稍后使用 XrayR log 查看日志信息，若无法启动，则可能更改了配置格式，请前往 wiki 查看：https://github.com/XrayR-project/XrayR/wiki${plain}"
        fi
    fi
    # 安装管理工具
    XrayR_tool
    echo ""
    echo "安装完成，正在尝试重启XrayR服务..."
    echo
    XrayR restart
    echo "正在关闭防火墙！"
    echo
    systemctl disable firewalld
    systemctl stop firewalld
    echo "XrayR服务已经完成重启，请愉快地享用！"
    pause_press
}

XrayR_tool(){
    echo
    if [[ ! -f usr/bin/XrayR ]]; then
        curl -o /usr/bin/XrayR -Ls https://raw.githubusercontent.com/XrayR-project/XrayR-release/master/XrayR.sh
        chmod +x /usr/bin/XrayR      
    fi
    echo -e ""
    echo "XrayR 管理脚本使用方法: "
    echo "------------------------------------------"
    echo "XrayR                    - 显示管理菜单 (功能更多)"
    echo "XrayR restart            - 重启 XrayR"
    echo "XrayR status             - 查看 XrayR 状态"
    echo "XrayR log                - 查看 XrayR 日志"
    echo "XrayR config             - 显示配置文件内容"
    echo "XrayR start              - 启动 XrayR"
    echo "XrayR stop               - 停止 XrayR"
    echo "XrayR enable             - 设置 XrayR 开机自启"
    echo "XrayR disable            - 取消 XrayR 开机自启"
    echo "XrayR update             - 更新 XrayR"
    echo "XrayR update x.x.x       - 更新 XrayR 指定版本"
    echo "XrayR install            - 安装 XrayR"
    echo "XrayR uninstall          - 卸载 XrayR"
    echo "XrayR version            - 查看 XrayR 版本"
    echo "------------------------------------------"
    pause_press
}

# 菜单
menu(){
	clear
	echo
	echo -e "\t1.安装XrayR"
	echo -e "\t2.新增nodes"
	echo -e "\t3.安装acme"
	echo -e "\t4.显示XrayR命令"
	echo -e "\t0.退出\n"
	echo -en "请输入数字选项回车: "
    # read -p "请输入数字[1-4]:" menu_Num
    read -n 1 option
}
while [ 1 ]
do
	menu
    # case "$menu_Num" in
	case "$option" in
		0)
		break
		;;
		1)
		install_XrayR $1
		;;
		2)
		config_nodes
        config_set
        config_modify
        systemctl restart XrayR
        sleep 5
        systemctl -l status XrayR
		;;
		3)
		install_acme
		;;
		4)
		XrayR_tool
		;;
		*)
		echo "请输入正确数字[1-4]:"
		;;
	esac
done
clear