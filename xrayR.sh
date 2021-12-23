#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)
config_ymlfile="/etc/XrayR/config.yml"
config_rulefile="/etc/XrayR/rulelist"
config_dnsfile="/etc/XrayR/dns.json"
tls_path="/etc/XrayR/cert/certificates"
config_Caddyfile="/etc/caddy/Caddyfile"
caddy_www="https://github.com/cdnf/shell/raw/master/resource/www.zip"
stable_version="v0.7.2"
# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用root用户运行此脚本！\n" && exit 1

# 安装基础依赖
dependency="wget curl git unzip gzip tar screen lrzsz socat ntpdate jq"
if [[ -f /usr/bin/apt && -f /bin/systemctl ]] || [[ -f /usr/bin/yum && -f /bin/systemctl ]]; then
    if [[ -f /usr/bin/yum ]]; then
        os="centos"
        cmd="yum"
        cron_srv="crond"
        $cmd -y install epel-release crontabs bind-utils
    fi
    if [[ -f /usr/bin/apt ]]; then
        os="debian"
        cmd="apt"
        cron_srv="cron"
        $cmd -y install cron dnsutils
    fi
    $cmd -y update
    $cmd -y install ${dependency}
else
    echo -e "${red}未检测到系统版本，本程序只支持CentOS，Ubuntu和Debian！，如果检测有误，请联系作者${plain}\n" && exit 1
fi
sys_bit=$(uname -m)
if [[ ${sys_bit} != "x86_64" ]]; then
    echo "本软件不支持 32 位系统(x86)，请使用 64 位系统(x86_64)，如果检测有误，请联系作者"
    exit 2
fi
#设置时区为东八区
echo yes | cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
#添加系统定时任务自动同步时间并把写入到BIOS，重启定时任务服务
sed -i '/^.*ntpdate*/d' /etc/crontab
sed -i '$a\0 1 * * 1 root ntpdate cn.pool.ntp.org >> /dev/null 2>&1' /etc/crontab
hwclock -w && systemctl restart ${cron_srv}

# 实现按任意键继续
get_char() {
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2>/dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}
pause_press() {
    # 启用功能的开关 1开启|其它不开启
    enable_pause=1

    # 判断第一个参数是否为空，约定俗成的写法
    if [ "x$1" != "x" ]; then
        echo $1
    fi
    if [ $enable_pause -eq 1 ]; then
        # echo "Press any key to continue!"
        echo "按任意键继续!"
        char=$(get_char)
    fi
}

# Writing json
# 配置文件说明：https://crackair.gitbook.io/xrayr-project/xrayr-pei-zhi-wen-jian-shuo-ming/config
config_init() {
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
config_nodes() {
    if [[ ! -f ${config_ymlfile} ]]; then
        echo "配置文件不存在，请确认已安装XrayR"
        exit 1
    else
        cat >>${config_ymlfile} <<EOF
    -
        PanelType: "${Panel_Type}" # Panel type: SSpanel, V2board, PMpanel, Proxypanel
        ApiConfig:
            ApiHost: "${Api_Host}"
            ApiKey: "${Api_Key}"
            NodeID: "${Node_ID}"
            NodeType: "${Node_Type}" # Node type: V2ray, Trojan, Shadowsocks, Shadowsocks-Plugin
            Timeout: 30 # Timeout for the api request
            EnableVless: ${Enable_Vless} # Enable Vless for V2ray Type
            EnableXTLS: ${Enable_XTLS} # Enable XTLS for V2ray and Trojan
            SpeedLimit: 0 # Mbps, Local settings will replace remote settings, 0 means disable
            DeviceLimit: 0 # Local settings will replace remote settings, 0 means disable
            RuleListPath: "Rule_List" # ./rulelist Path to local rulelist file
        ControllerConfig:
            ListenIP: 0.0.0.0 # IP address you want to listen
            SendIP: 0.0.0.0 # IP address you want to send pacakage
            UpdatePeriodic: 60 # Time to update the nodeinfo, how many sec.
            EnableDNS: false # Use custom DNS config, Please ensure that you set the dns.json well
            DNSType: AsIs # AsIs, UseIP, UseIPv4, UseIPv6, DNS strategy
            DisableUploadTraffic: false # Disable Upload Traffic to the panel
            DisableGetRule: false # Disable Get Rule from the panel
            DisableIVCheck: false # Disable the anti-reply protection for Shadowsocks 
            EnableProxyProtocol: false # Only works for WebSocket and TCP
            EnableFallback: ${Enable_Fallback} # Only support for Trojan and Vless
            FallBackConfigs: # Support multiple fallbacks
                -
                    SNI: # TLS SNI(Server Name Indication), Empty for any
                    Path: # HTTP PATH, Empty for any
                    Dest: "www.amazon.com:80" # Required, Destination of fallback, check https://xtls.github.io/config/fallback/ for details.
                    ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for disable
EOF
        echo -e "节点配置已写入 ${green}${config_ymlfile}${plain}"
    fi
}
config_Cert() {
    cat >>${config_ymlfile} <<EOF
            CertConfig:
                CertMode: "${Cert_Mode}" # Option about how to get certificate: none, file, http, dns. Choose "none" will forcedly disable the tls config.
                CertDomain: "${Cert_Domain}" # Domain to cert
                CertFile: "${tls_path}/${Cert_Domain}.crt" # Provided if the CertMode is file
                KeyFile: "${tls_path}/${Cert_Domain}.key" # http filepath is /etc/XrayR/cert/certificates/
                Email: "${Cert_Email}"
EOF
}
config_Provider_dnspod() {
    cat >>${config_ymlfile} <<EOF
                Provider: "dnspod" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    DNSPOD_API_KEY: "${ACCESS_KEY}"
EOF
}
config_Provider_cloudflare() {
    cat >>${config_ymlfile} <<EOF
                Provider: "cloudflare" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    CF_API_EMAIL: "${CF_USER}"
                    CF_API_KEY: "${ACCESS_KEY}"
                    # CF_DNS_API_TOKEN: "${SECRET_KEY}"
EOF
}
config_Provider_namesilo() {
    cat >>${config_ymlfile} <<EOF
                Provider: "namesilo" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    NAMESILO_API_KEY: "${ACCESS_KEY}"
EOF
}

config_dns_Provider() {
    # acme的配置用法：https://github.com/acmesh-official/acme.sh/wiki/dnsapi
    if [[ ${dns_Provider} == "dnspod" ]]; then
        dns_Provider_acme="dns_dp"
        read -p "请输入DNSPod Token ID：" dp_TokenId
        read -p "请输入DNSPod Token：" dp_Token
        export DP_Id="${dp_TokenId}"
        export DP_Key="${dp_Token}"
        # read -p "DNSPOD_API_KEY [Token]: " ACCESS_KEY
        ACCESS_KEY=${dp_TokenId},${dp_Token}
    elif [[ ${dns_Provider} == "namesilo" ]]; then
        dns_Provider_acme="dns_namesilo"
        read -p "请输入Namesilo Key:" ACCESS_KEY
        export Namesilo_Key="${ACCESS_KEY}"
    else
        echo "默认DNS托管在 cloudflare"
        dns_Provider_acme="dns_cf"
        read -p "请输入CF 邮箱:" CF_USER
        read -p "请输入CF Global Key:" ACCESS_KEY
        export CF_Key="${ACCESS_KEY}"
        export CF_Email="${CF_USER}"
    fi
}

config_XrayR_dns() {
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
# 生成本地审计规则rulelist
config_audit() {
    cat >${config_rulefile} <<EOF
(.*\.||)(gov|12377|12315|12321)\.(org|com|cn|net)
(api|ps|sv|offnavi|newvector|ulog\.imap|newloc)(\.map|)\.(baidu|n\.shifen)\.(com|cn)
(.*\.||)(360|so|qq|163|sohu|sogoucdn|sogou|uc|58|taobao|qpic)\.(org|com|net|cn)
(.*\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\.(org|com|net)
(.*\.||)(shenzhoufilm|secretchina|renminbao|aboluowang|mhradio|guangming|zhengwunet|soundofhope|yuanming|zhuichaguoji|fgmtv|xinsheng|shenyunperformingarts|epochweekly|tuidang|shenyun|falundata|bannedbook)\.(org|com|net)
(.*\.||)(icbc|ccb|boc|bankcomm|abchina|cmbchina|psbc|cebbank|cmbc|pingan|spdb|citicbank|cib|hxb|bankofbeijing|hsbank|tccb|4001961200|bosc|hkbchina|njcb|nbcb|lj-bank|bjrcb|jsbchina|gzcb|cqcbank|czbank|hzbank|srcb|cbhb|cqrcb|grcbank|qdccb|bocd|hrbcb|jlbank|bankofdl|qlbchina|dongguanbank|cscb|hebbank|drcbank|zzbank|bsb|xmccb|hljrcc|jxnxs|gsrcu|fjnx|sxnxs|gx966888|gx966888|zj96596|hnnxs|ahrcu|shanxinj|hainanbank|scrcu|gdrcu|hbxh|ynrcc|lnrcc|nmgnxs|hebnx|jlnls|js96008|hnnx|sdnxs)\.(org|com|net|cn|bank)
(.*\.||)(unionpay|alipay|baifubao|yeepay|99bill|95516|51credit|cmpay|tenpay|lakala|jdpay|mycard)\.(org|com|cn|net)
(.*\.||)(firstbank|bot|cotabank|megabank|tcb-bank|landbank|hncb|bankchb|tbb|ktb|tcbbank|scsb|bop|sunnybank|kgibank|fubon|ctbcbank|cathaybk|eximbank|bok|ubot|feib|yuantabank|sinopac|esunbank|taishinbank|jihsunbank|entiebank|hwataibank|csc|skbank|.*bank)\.(org|com|cn|net|tw)
(.*\.||)(metatrader4|metatrader5|mql5)\.(org|com|net)
(.*\.||)(2miners|666pool|91pool|atticpool|anomp|aapool|antpool|globalpool|miningpoolhub|blackpool|blockmasters|btchd|bitminter|bitcoin|bhdpool|bginpool|baimin|bi-chi|bohemianpool|bixin|bwpool|btcguild|batpool|bw|btcc|btc|btc|bitfury|bitclubnetwork|beepool|coinhive|chainpool|connectbtc|cybtc|canoepool|cryptograben|cryptonotepool|coinotron|dashcoinpool|dxpool|dwarfpool|dpool|dpool|dmpools|everstake|epool|ethpool|ethfans|easy2mine|ethermine|extremepool|firepool|fir|fkpool|flypool|f3pool|gridcash|gath3r|grin-pool|grinmint|c3pool|gbminers|get.bi-chi|globalpool|give-me-ltc|yminer|stmining|hashquark|hashrabbit|hummerpool|hdpool|h-pool|hashvault|hpool|huobipool)\.(org|com|cn|net|cc|co|io|one|pro|info|im)
EOF
    # Poseidon规则配置需「regexp:」语句打头
}
# 生成邮箱账号
config_Email() {
    if [[ -z ${Cert_Domain} ]]; then
        read -p "请输入解析到本机的域名:" Cert_Domain
    fi
    # local Cert_Email_Account=$(((RANDOM << 9)))
    # Cert_Email=${Cert_Email_Account}@gmail.com
    # 默认为二级子域名，取域名中第一个”.“右侧到结尾字符串
    Cert_Email=admin@${Cert_Domain#*\.}
}

config_GetNodeInfo() {
    # 只做了v2board适配，需指定Node_ID，Node_Type，Cert_Domain，方便对接caddy2
    # "V2ray":"${Api_Host}/api/v1/server/Deepbwork/config?token=${Api_Key}&node_id=${Node_ID}&local_port=1"
    # "Trojan":"${Api_Host}/api/v1/server/TrojanTidalab/config?token=${Api_Key}&node_id=${Node_ID}&local_port=1"
    if [[ "$Node_Type" == "V2ray" ]]; then
        # 获取后端inbound.{port,protocol，streamSettings.{security,wsSettings.path}}
        NodeInfo_url="${Api_Host}/api/v1/server/Deepbwork/config?token=${Api_Key}&node_id=${Node_ID}&local_port=1"
        NodeInfo_json=$(curl "${NodeInfo_url}" | jq '.inbound')
        # 监听端口：443，回落或与caddy对接
        inbound_port=$(echo ${NodeInfo_json} | jq -r '.port')
        # 使用协议：vmess|vless|Trojan，决定是否启用xtls等
        inbound_protocol=$(echo ${NodeInfo_json} | jq -r '.protocol')
        # 加密方式：tls|xtls|none
        network_security=$(echo ${NodeInfo_json} | jq -r '.streamSettings.security')
        # 传输协议：tcp|grpc|ws才对接caddy
        network_protocol=$(echo ${NodeInfo_json} | jq -r '.streamSettings.network')
        # 分流路径，回落对接用
        network_path=$(echo ${NodeInfo_json} | jq -r '.streamSettings.wsSettings.path')
    elif [[ "$Node_Type" == "Trojan" ]]; then
        # 获取后端local_port，remote_port，remote_addr，ssl.sni
        NodeInfo_url="${Api_Host}/api/v1/server/TrojanTidalab/config?token=${Api_Key}&node_id=${Node_ID}&local_port=1"
        NodeInfo_json=$(curl "${NodeInfo_url}" | jq '.')
        # 监听端口：443，回落或与caddy对接
        inbound_port=$(echo ${NodeInfo_json} | jq -r '.local_port')
        # 使用协议：vmess|vless|Trojan，决定是否启用xtls等
        inbound_protocol="Trojan"
        # 加密方式：tls|xtls|none
        network_security=$(echo ${NodeInfo_json} | jq -r '.ssl')
        # 传输协议：tcp|grpc|ws才对接caddy,v2board默认只有tcp
        network_protocol="tcp"
        # 分流serverName，回落对接用
        network_sni=$(echo ${NodeInfo_json} | jq -r '.ssl.sni')
    else
        echo -e "SS的GetNodeInfo接口看不懂，「port」不知道从哪来，刚好也不知道SS能不能伪装分流……"
    fi
    echo
    echo -e "从 ${green}${Api_Host}${plain} 获取 ${green}${Node_ID}${plain} 号 ${green}${Node_Type}${plain} 节点信息完成"
}

# Pre-installation settings
config_set() {
    echo
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

    read -p "前端面板认证域名(包括http[s]://):" Api_Host
    [ -z "${Api_Host}" ] && Api_Host="http://1.1.1.1"
    read -p "前端面板的apikey:" Api_Key
    [ -z "${Api_Key}" ] && Api_Key="abc123"

    echo -e "[1] V2ray \t [2] Trojan \t [3] Shadowsocks"
    read -p "节点类型（默认V2ray）:" node_num
    [ -z "${node_num}" ] && node_num="1"
    if [[ "$node_num" == "1" ]]; then
        Node_Type="V2ray"
    elif [[ "$node_num" == "2" ]]; then
        Node_Type="Trojan"
    elif [[ "$node_num" == "3" ]]; then
        Node_Type="Shadowsocks"
    else
        echo "type error, please try again"
        exit
    fi

    read -p "前端节点信息里面的节点ID:" Node_ID
    [ -z "${Node_ID}" ] && Node_ID=1

    read -p "请输入解析到本机的域名:" Cert_Domain
    config_Email
    # 从面板获取节点关键信息
    config_GetNodeInfo

    echo
    echo -e "\t面板类型：${green}${Panel_Type}${plain}"
    echo -e "\t面板域名「apihost」：${green}${Api_Host}${plain}"
    echo -e "\t面板apikey「token」：${green}${Api_Key}${plain}"
    echo -e "\t节点类型「Node_Type」：${green}${Node_Type}${plain}"
    echo -e "\t节点ID「node_id」：${green}${Node_ID}${plain}"
    echo -e "\t节点域名「Cert_Domain」：${green}${Cert_Domain}${plain}"
    echo -e "\t监听端口「port」：${green}${inbound_port}${plain}"
    echo -e "\t使用协议「protocol」：${green}${inbound_protocol}${plain}"
    echo -e "\t安全加密「tls」：${green}${network_security}${plain}"
    echo -e "\t传输协议「network」：${green}${network_protocol}${plain}"
    if [[ "$Node_Type" == "V2ray" ]]; then
        echo -e "\t分流路径「path」：${green}${network_path}${plain}"
    fi
    if [[ "$Node_Type" == "Trojan" ]]; then
        echo -e "\t分流SNI「serverName」：${green}${network_sni}${plain}"
    fi
    echo
    echo -e "请确认以上信息是否正确，如果不正确请按${yellow} Ctrl+C ${plain}取消重来"
    pause_press

    # 规则组合：https://github.com/XTLS/Xray-examples
    # echo
    # echo -e "v2board暂不支持VLESS，先写好等面板支持"
    # echo -e "========================================================="
    # echo -e "1. VLESS+TCP+XTLS「☆☆☆☆☆Xray前置回落到caddy时用，号称最强性能」"
    # echo -e "2. VLESS+WS+TLS「☆☆☆☆带伪装，支持CDN」"
    # echo -e "3. VMESS+WS+TLS「☆☆☆☆带伪装，支持CDN」"
    # echo -e "4. VMESS+WS「☆☆☆中转配不好证书的时候直接用」"
    # echo -e "5. VLESS+WS「☆☆☆中转配不好证书的时候直接用」"
    # echo -e "6. VLESS+gRPC+TLS「☆Xray前置回落到caddy时用」"
    # echo -e "7. Trojan+gRPC+TLS「☆☆延迟低，支持CDN」"
    # echo -e "8. Trojan+XTLS「☆☆☆☆高性能小马」"
    # echo -e "========================================================="
    # read -p "请选择规则组合（默认3）：" rules_num
    #     [ -z "${rules_num}" ] && rules_num="3"
    # if [[ "$rules_num" == "1" ]]; then
    #     Enable_Vless="true"
    #     Enable_XTLS="true"
    # elif [[ "$rules_num" =~ (2|5|6) ]]; then
    #     Enable_Vless="true"
    #     Enable_XTLS="false"
    # elif [[ "$rules_num" =~ (3|4|7) ]]; then
    #     Enable_Vless="false"
    #     Enable_XTLS="false"
    # elif [[ "$rules_num" == "8" ]]; then
    #     Enable_Vless="false"
    #     Enable_XTLS="true"
    # else
    #     echo "type error, please try again"
    #     exit
    # fi

    install_Caddy

    echo -e "========================================================="
    echo -e "1. Caddy:{80,443} --> XrayR"
    echo -e "2. XrayR:{80,443} --> Caddy"
    echo -e "========================================================="
    read -p "请选择方案组合（默认 1）：" rules_num
    [ -z "${rules_num}" ] && rules_num="1"
    if [[ "$rules_num" == "1" ]]; then
        echo
        echo -e "由Caddy或Acme管理ssl证书，关闭XrayR证书管理功能"
        is_tls="0"
        if [[ ${inbound_port} == "443" || ${inbound_port} == "80" ]]; then
            echo "后端服务不可设置为 443 或 80，请到面板修改为其他端口"
            exit 2
        fi
        config_caddy
    elif [[ "$rules_num" == "2" ]]; then
        # 是否启用tls
        if [[ ${network_security} == "tls" || ${network_security} == "xtls" ]]; then
            is_tls="1"
        else
            is_tls="0"
        fi
    else
        echo "type error, please try again"
        exit
    fi

    if [[ ${network_security} == "xtls" ]]; then
        Enable_XTLS="true"
    else
        Enable_XTLS="false"
    fi
    if [[ ${inbound_protocol} == "vless" ]]; then
        Enable_Vless="true"
    else
        Enable_Vless="false"
    fi
    if [[ "$Node_Type" == "V2ray" || "$Node_Type" == "Trojan" ]]; then
        if [[ "$is_tls" == "1" ]]; then
            echo -e "[1] http \t [2] file \t [3] dns"
            read -p "证书认证模式（默认http）:" Cert_Mode_num
            [ -z "${Cert_Mode_num}" ] && Cert_Mode_num="1"
            if [[ "${Cert_Mode_num}" == "2" ]]; then
                Cert_Mode="file"
            elif [[ "${Cert_Mode_num}" == "3" ]]; then
                Cert_Mode="dns"
                echo -e "[1] cloudflare \t [2] dnspod \t [3] namesilo"
                read -p "DNS托管商:" dns_Provider_num
                if [[ "${dns_Provider_num}" == "2" ]]; then
                    dns_Provider="dnspod"
                elif [[ "${dns_Provider_num}" == "3" ]]; then
                    dns_Provider="namesilo"
                else
                    dns_Provider="cloudflare"
                fi
                config_dns_Provider
            else
                Cert_Mode="http"
            fi
        else
            Cert_Mode="none"
        fi
    fi
    if [[ "$Node_Type" == "Trojan" || "$Enable_Vless" == "true" ]]; then
        Enable_Fallback="true"
    else
        Enable_Fallback="false"
    fi
}
config_modify() {
    config_Cert
    # V2board启用本地审计
    if [[ "${Panel_Type}" == "V2board" ]] && [[ "${Node_Type}" == "Trojan" || "${Node_Type}" == "Shadowsocks" ]]; then
        echo -e "V2board不支持在线同步规则，将启用本地规则……"
        config_audit
        sed -i "s|\"Rule_List\"|\"${config_rulefile}\"|" ${config_ymlfile}
    else
        sed -i "s|\"Rule_List\"||" ${config_ymlfile}
    fi
    if [[ "$rules_num" == "2" ]]; then
        echo
        echo -e "由XrayR管理ssl证书"
    elif [[ "${dns_Provider}" == "dnspod" ]]; then
        config_Provider_dnspod
    elif [[ "${dns_Provider}" == "namesilo" ]]; then
        config_Provider_namesilo
    elif [[ "${dns_Provider}" == "cloudflare" ]]; then
        config_Provider_cloudflare
    else
        echo -e "未选择dns认证，跳过……"
        echo -e "如不符合预期请自行检查 ${green}${config_ymlfile}${plain}"
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
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

install_Caddy() {
    # 官网选的 CF+dnspod+alidns 插件下载链接，可用"caddy list-modules"命令查看
    caddy_url="https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com/caddy-dns/cloudflare&p=github.com/caddy-dns/dnspod"
    wget -N --no-check-certificate -O "/usr/bin/caddy" ${caddy_url}
    chmod +x "/usr/bin/caddy"
    groupadd --system caddy
    useradd --system \
        --gid caddy \
        --create-home \
        --home-dir /srv/www \
        --shell /usr/sbin/nologin \
        --comment "Caddy web server" \
        caddy

    caddy_service="https://raw.githubusercontent.com/caddyserver/dist/master/init/caddy.service"
    wget -N --no-check-certificate -O "/etc/systemd/system/caddy.service" ${caddy_service}
    echo
    echo -e "${green}Caddy2 安装完成${plain}"
}
install_www() {
    # 放个小游戏到/srv/www
    wget --no-check-certificate -O www.zip $caddy_www
    unzip -o www.zip -d /srv/ && rm -f www.zip
    systemctl daemon-reload && systemctl enable caddy
    echo
    echo -e "${green}Caddy2 安装完成${plain}"
}
config_caddy() {
    # keys：domain，port，tls，path/sni
    # caddy监控443和80，通过path分流到后端，所以后端服务不能设置这两个端口
    if [[ ! -d "/etc/caddy" ]]; then
        mkdir -p /etc/caddy
    fi
    cp -f ${config_Caddyfile}{,_$(date +"%Y%m%d")}
    cat >${config_Caddyfile} <<EOF
${Cert_Domain} {
    root * /srv/www
    file_server
    encode gzip
    tls ${Cert_Email}
    log {
        output file /srv/www/caddy.log
    }
    @websocket {
        path ${network_path}
        header Connection *Upgrade*
        header Upgrade websocket
    }
    reverse_proxy @websocket localhost:${inbound_port}
}
EOF
    install_www
    systemctl restart caddy
}

tls_acme_install() {
    if [[ ! -f "~/.acme.sh/acme.sh" ]]; then
        echo -e "${green}开始安装 acme${plain}"
        curl https://get.acme.sh | sh
        echo -e "${green}acme 安装完成${plain}"
    else
        echo -e "acme已经在系统里了..."
    fi
    # 开启自动升级
    acme.sh --upgrade --auto-upgrade
}
tls_acme_register() {
    # https://github.com/acmesh-official/acme.sh/wiki/Server
    acme.sh --register-account -m ${Cert_Email} --server zerossl
    # acme.sh --set-default-ca  --server letsencrypt
}
tls_acme_obtain() {
    # 使用 acme.sh 生成证书
    if [[ ${Cert_Domain##*.} =~ (cf|ga|gq|ml|tk) ]]; then
        echo "cloudflare不支持这些域名api方式管理：.cf, .ga, .gq, .ml, .tk"
        echo -e "使用http方式申请"
        acme.sh --issue -d ${Cert_Domain} --httpport 6969 --standalone -k ec-256
    else
        config_DNS
        acme.sh --issue -d ${Cert_Domain} --dns ${dns_Provider_acme} -k ec-256
    fi
    tls_acme_deploy
}
tls_acme_deploy() {
    if [ ! -d "${tls_path}" ]; then
        mkdir -p ${tls_path}
    fi
    acme.sh --installcert -d ${Cert_Domain} --fullchain-file ${tls_path}/${Cert_Domain}.crt --key-file ${tls_path}/${Cert_Domain}.key --ecc
    XrayR restart
    # 加个保险每2个月定时自动部署一次，防止acme自动更新未部署到 $tls_path
    sed -i '/^.*acme.*\.cert\/.*/d' /var/spool/cron/root
    echo "0 0 1 */2 * acme.sh --installcert -d ${Cert_Domain} --fullchain-file ${tls_path}/${Cert_Domain}.crt --key-file ${tls_path}/${Cert_Domain}.key --ecc" >>/var/spool/cron/root
}

install_XrayR() {
    echo
    echo -e "${green}开始安装 XrayR${plain}"
    if [[ -e /usr/local/XrayR/ ]]; then
        rm -rf /usr/local/XrayR/
    fi

    mkdir -p /usr/local/XrayR/
    cd /usr/local/XrayR/

    if [[ $# == 0 ]]; then
        last_version=$(curl -Ls "https://api.github.com/repos/XrayR-project/XrayR/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ -z "$last_version" ]]; then
            echo -e "获取最新版本失败，使用默认版本"
            last_version="${stable_version}"
        fi
        echo -e "开始安装 XrayR 版本：${last_version}"
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
    systemctl daemon-reload && systemctl stop XrayR
    systemctl enable XrayR
    echo -e "${green}XrayR ${last_version}${plain} 安装完成，已设置开机自启"
    mkdir -p /etc/XrayR/
    cp geoip.dat /etc/XrayR/
    cp geosite.dat /etc/XrayR/

    if [[ ! -f /etc/XrayR/dns.json ]]; then
        config_XrayR_dns
    fi

    if [[ ! -f ${config_ymlfile} ]]; then
        config_set
        config_init && config_nodes
        config_modify
        echo
        echo -e "全新安装完成，更多内容请见：https://github.com/XrayR-project/XrayR"
    else
        systemctl start XrayR
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo
            echo -e "${green}XrayR 重启成功${plain}"
        else
            echo
            echo -e "${red}XrayR 可能启动失败，请稍后使用 XrayR log 查看日志信息，若无法启动，则可能更改了配置格式，请前往 wiki 查看：https://github.com/XrayR-project/XrayR/wiki${plain}"
        fi
    fi
    # 安装管理工具
    XrayR_tool
    echo
    echo "安装完成，正在尝试重启XrayR服务..."
    echo
    XrayR restart
    if [[ -f /usr/sbin/firewalld ]]; then
        echo "正在关闭防火墙！"
        systemctl disable firewalld
        systemctl stop firewalld
    fi
    echo
    echo "XrayR服务已经完成重启，请愉快地享用！"
    pause_press
}

XrayR_tool() {
    echo
    if [[ ! -f usr/bin/XrayR ]]; then
        curl -o /usr/bin/XrayR -Ls https://raw.githubusercontent.com/XrayR-project/XrayR-release/master/XrayR.sh
        chmod +x /usr/bin/XrayR
    fi
}

# 菜单
menu() {
    echo
    echo -e "======================================"
    echo -e "	Author: 金将军"
    echo -e "	Version: 2.0.0"
    echo -e "======================================"
    echo
    echo -e "\t1.安装XrayR"
    echo -e "\t2.新增nodes"
    echo -e "\t3.安装acme"
    echo -e "\t4.安装Caddy2"
    echo -e "\t9.卸载XrayR"
    echo -e "\t0.退出\n"
    echo -en "\t请输入数字选项: "
    # read -p "请输入数字选项: " menu_Num
    read -n 1 option
}
while [ 1 ]; do
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
        config_set
        config_nodes && config_modify
        systemctl restart XrayR && systemctl -l status XrayR
        ;;
    3)
        tls_acme_install
        ;;
    4)
        install_Caddy
        ;;
    9)
        XrayR_tool
        XrayR uninstall
        ;;
    *)
        echo "请输入正确数字:"
        ;;
    esac
done
clear
