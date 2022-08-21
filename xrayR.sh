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
tls_path="/srv/.cert"
web_2048="https://github.com/cdnf/shell/raw/master/resource/www.zip"
# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用root用户运行此脚本！\n" && exit 1

# 安装基础依赖
dependency="wget curl git unzip gzip tar screen lrzsz socat ntpdate jq cron dnsutils"
if [[ -f /usr/bin/apt && -f /bin/systemctl ]]; then
    os="debian"
    cron_srv="cron"
    INS="apt -y install"
    apt -y update
    apt remove -y httpd
    $INS ${dependency}
else
    echo -e "${red}未检测到系统版本，本垃圾程序只支持Debian！，如果检测有误，请联系作者${plain}\n" && exit 1
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
get_Swap() {
    swap_now=$(swapon --show)
    if [[ -z $swap_now ]]; then
        fallocate -l 1G /swap
        chmod 600 /swap
        mkswap /swap
        swapon /swap
        sed -i "/^\/swap/d" /etc/fstab
        echo "/swap swap swap defaults 0 0" >>/etc/fstab
    else
        echo
        echo -e "交换分区已存在，什么都不做"
    fi
    swapon --show
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
InboundConfigPath: # /etc/XrayR/custom_inbound.json # Path to custom inbound config, check https://xtls.github.io/config/inbound.html for help
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
            EnableProxyProtocol: ${Enable_ProxyProtocol} # Only works for WebSocket and TCP
            EnableFallback: ${Enable_Fallback} # Only support for Trojan and Vless
            FallBackConfigs: # Support multiple fallbacks
                -
                    SNI: # TLS SNI(Server Name Indication), Empty for any
                    Path: # HTTP PATH, Empty for any
                    Dest: "80" # Required, Destination of fallback, check https://xtls.github.io/config/features/fallback.html for details.
                    ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for disable
EOF
        echo -e "节点配置已写入 ${green}${config_ymlfile}${plain}"
    fi
}
config_Cert() {
    cat >>${config_ymlfile} <<EOF
            CertConfig:
                CertMode: "${Cert_Mode}" # Option about how to get certificate: none, file, http, dns. Choose "none" will forcedly disable the tls config.
                CertDomain: "${Domain_SNI}" # Domain to cert
                CertFile: "${TLS_CertFile}" # Provided if the CertMode is file
                KeyFile: "${TLS_KeyFile}" # http default in /etc/XrayR/cert/certificates/
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
        read -p "请输入CF Account ID:" CF_USER
        read -p "请输入CF SSL Token:" ACCESS_KEY
        export CF_Account_ID="${CF_USER}"
        export CF_Token="${ACCESS_KEY}"
        # read -p "请输入CF 邮箱:" CF_USER
        # read -p "请输入CF Global Key:" ACCESS_KEY
        # export CF_Key="${ACCESS_KEY}"
        # export CF_Email="${CF_USER}"
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
(.*\.||)(360|so|qq|163|sohu|sogoucdn|sogou|uc|58|taobao|qpic|weibo|toutiao|bilibili|douyin|kuaishou|xiaohongshu)\.(org|com|net|cn|io)
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
    # local Cert_Email_Account=$(((RANDOM << 9)))
    # Cert_Email=${Cert_Email_Account}@gmail.com
    # 默认为二级子域名，${Domain_Srv#*\.} 取域名中第一个”.“右侧到结尾字符串
    Cert_Email=admin@${Domain_Srv#*\.}
}

config_GetNodeInfo() {
    # 只做了v2board适配，需指定Node_ID，Node_Type，Domain_Srv，方便对接caddy2
    # "V2ray":"${Api_Host}/api/v1/server/Deepbwork/config?token=${Api_Key}&node_id=${Node_ID}&local_port=1"
    # "Trojan":"${Api_Host}/api/v1/server/TrojanTidalab/config?token=${Api_Key}&node_id=${Node_ID}&local_port=1"
    # "Shadowsocks":${Api_Host}/api/v1/server/ShadowsocksTidalab/user?token=${Api_Key}&node_id=${Node_ID}&local_port=1
    if [[ "$Node_Type" == "V2ray" ]]; then
        # 获取后端inbound.{port,protocol，streamSettings.{security,wsSettings.path}}
        NodeInfo_url="${Api_Host}/api/v1/server/Deepbwork/config?token=${Api_Key}&node_id=${Node_ID}&local_port=1"
        NodeInfo_json=$(curl "${NodeInfo_url}" | jq '.inbounds[0]')
        # 监听端口：443，回落或与caddy对接
        inbound_port=$(echo ${NodeInfo_json} | jq -r '.port')
        # 使用协议：vmess|vless|Trojan，决定是否启用xtls等
        inbound_protocol=$(echo ${NodeInfo_json} | jq -r '.protocol')
        # 加密方式：tls|xtls|none
        network_security=$(echo ${NodeInfo_json} | jq -r '.streamSettings.security')
        # 传输协议：tcp|grpc|ws才对接caddy
        network_protocol=$(echo ${NodeInfo_json} | jq -r '.streamSettings.network')
        # 分流serverName，回落对接用
        network_sni=${Domain_SNI}
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
        # 加密方式：tls|xtls|none，Trojan强制tls
        network_security="tls"
        # 传输协议：tcp|grpc|ws才对接caddy,v2board默认只有tcp
        network_protocol="tcp"
        # 分流serverName，回落对接用
        network_sni=$(echo ${NodeInfo_json} | jq -r '.ssl.sni')
    elif [[ "$Node_Type" == "Shadowsocks" ]]; then
        # 获取后端port，没有config函数，只能从用户接口中获取一个后端端口，其他写死
        NodeInfo_url="${Api_Host}/api/v1/server/ShadowsocksTidalab/user?token=${Api_Key}&node_id=${Node_ID}&local_port=1"
        NodeInfo_json=$(curl "${NodeInfo_url}" | jq '.data[0]')
        # 监听端口：443，回落或与caddy对接
        inbound_port=$(echo ${NodeInfo_json} | jq -r '.port')
        # 没有这项，直接写死
        inbound_protocol="Shadowsocks"
        # 加密方式：tls|xtls|none，没有这项，直接写死tls
        network_security="tls"
        # 传输协议：tcp|grpc|ws才对接caddy,v2board默认只有tcp
        network_protocol="tcp"
        # 分流serverName，回落对接用
        network_sni=${Domain_SNI}
        # 分流路径，回落对接用，没有接口，直接写死
        network_path="/services"
    else
        echo -e "${red}未知节点类型，或者接口不通，请检查${plain}"
        pause_press
        config_set
    fi
    if [[ -z ${NodeInfo_json} ]]; then
        echo "接口获取数据失败，请确保api地址畅通且授权正确"
        pause_press
        config_set
    fi
    echo
    echo -e "从 ${green}${Api_Host}${plain} 获取 ${green}${Node_ID}${plain} 号 ${green}${Node_Type}${plain} 节点信息完成"
}

# Pre-installation settings
config_set() {
    if [[ -z ${panel_num} ]]; then
        echo
        echo -e "[1] SSpanel \t [2] V2board"
        read -p "前端面板类型（默认V2board）：" panel_num
        [ -z "${panel_num}" ] && panel_num="2"
        if [ "$panel_num" == "1" ]; then
            Panel_Type="SSpanel"
        elif [ "$panel_num" == "2" ]; then
            Panel_Type="V2board"
        else
            echo "type error, please try again"
            pause_press
            config_set
        fi
    fi
    if [[ -z ${Api_Key} ]]; then
        read -p "前端面板认证域名（包括http[s]://）：" Api_Host
        [ -z "${Api_Host}" ] && Api_Host="http://1.1.1.1"
        read -p "前端面板的apikey：" Api_Key
        [ -z "${Api_Key}" ] && Api_Key="abc123"
    fi
    if [[ -z ${Domain_Main} ]]; then
        read -p "请输入欲使用的主域名，如 a.com：" Domain_Main
    fi
    # 默认cloudflare解析域名和申请证书
    CF_Token=$(cat ~/.acme.sh/account.conf | grep SAVED_CF_Token= | awk -F "'" '{print $2}')

    read -p "前端节点信息里面的节点ID：" Node_ID
    [ -z "${Node_ID}" ] && Node_ID=1

    Domain_Srv="${Node_ID}.${Domain_Main}"

    echo -e "[1] V2ray \t [2] Trojan \t [3] Shadowsocks"
    read -p "节点类型（默认V2ray）：" node_num
    [ -z "${node_num}" ] && node_num="1"
    if [[ "$node_num" == "1" ]]; then
        Node_Type="V2ray"
        Domain_SNI="v${Domain_Srv}"
        webserver_listen="2083"
    elif [[ "$node_num" == "2" ]]; then
        Node_Type="Trojan"
        Domain_SNI="t${Domain_Srv}"
        # webserver_listen="2096"
    elif [[ "$node_num" == "3" ]]; then
        Node_Type="Shadowsocks"
        Domain_SNI="s${Domain_Srv}"
        webserver_listen="2053"
    else
        echo "type error, please try again"
        pause_press
        config_set
    fi
    TLS_CertFile="${tls_path}/${Domain_SNI}.crt"
    TLS_KeyFile="${tls_path}/${Domain_SNI}.key"
    config_Email
    # 从面板获取节点关键信息
    config_GetNodeInfo
    if [[ ${inbound_port} == "443" || ${inbound_port} == "80" ]]; then
        echo "后端服务不可设置为 443 或 80，请到面板修改为其他端口"
        pause_press
        config_set
    fi

    echo
    echo -e "\t面板类型：${green}${Panel_Type}${plain}"
    echo -e "\t节点类型「Node_Type」：${green}${Node_Type}${plain}"
    echo -e "\t节点ID「node_id」：${green}${Node_ID}${plain}"
    echo -e "\t监听端口「port」：${green}${inbound_port}${plain}"
    echo -e "\t使用协议「protocol」：${green}${inbound_protocol}${plain}"
    echo -e "\t安全加密「tls」：${green}${network_security}${plain}"
    echo -e "\t传输协议「network」：${green}${network_protocol}${plain}"
    if [[ "$Node_Type" == "Trojan" ]]; then
        echo -e "\t分流SNI「serverName」：${green}${network_sni}${plain}"
    fi
    if [[ "$Node_Type" == "V2ray" ]]; then
        echo -e "\t分流路径「path」：${green}${network_path}${plain}"
        echo -e "\t分流SNI「serverName」：${green}${network_sni}${plain}"
    fi
    if [[ "$Node_Type" == "Shadowsocks" ]]; then
        echo -e "\t混淆路径「path」：${green}${network_path}${plain}"
        echo -e "\t混淆域名「serverName」：${green}${network_sni}${plain}"
    fi
    echo
    read -p "以上信息确认正确就回车继续，否则请输 N 重来：" Check_All
    if [[ ${Check_All} == "N" ]]; then
        config_set
    fi

    # 规则组合：https://github.com/XTLS/Xray-examples
    # 规则组合：https://github.com/lxhao61/integrated-examples
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
    # 只保留4层转发，可以cdn，伪装也方便
    echo -e "========================================================="
    echo -e "1. Caddy:{默认80,443} --> XrayR"
    echo -e "2. Nginx:{默认80,443} --> XrayR"
    echo -e "本脚本默认Caddy/Nginx伪装，要其他组合请后续自行修改配置"
    echo -e "========================================================="
    read -p "请选择方案组合（默认 2）：" rules_num
    [ -z "${rules_num}" ] && rules_num="2"

    if [[ "$rules_num" == "1" ]]; then
        systemctl disable nginx; systemctl stop nginx

        # caddy_config=Caddyfile或者Caddyfile.json
        caddy_config="/etc/caddy/Caddyfile.json"

        install_Caddy && config_caddy
        if [[ "$Node_Type" == "Trojan" ]]; then
            config_caddy_Trojan
        fi
        if [[ "$Node_Type" == "V2ray" ]]; then
            config_caddy_Vmess
        fi
        if [[ "$Node_Type" == "Shadowsocks" ]]; then
            config_caddy_Shadowsocks
        fi
        systemctl restart caddy
    elif [[ "$rules_num" == "2" ]]; then
        systemctl disable caddy; systemctl stop caddy
        if [[ ! $(nginx -v) ]]; then
            install_Nginx
        fi
        nginx_conf="/etc/nginx/nginx.conf"

        config_Nginx
        if [[ "$Node_Type" == "Trojan" ]]; then
            config_Nginx_Trojan
        fi
        if [[ "$Node_Type" == "V2ray" ]]; then
            config_Nginx_Vmess
        fi
        if [[ "$Node_Type" == "Shadowsocks" ]]; then
            config_Nginx_Shadowsocks
        fi
        systemctl restart nginx
    else
        echo
        echo "无法识别，请输入正确的数字，也不纠正了，装完自己改吧"
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

    if [[ "$Node_Type" == "Trojan" ]]; then
        Enable_Fallback="true"
        # 解决Trojan无法用nginx路径分流
        Enable_ProxyProtocol="true"
        Cert_Mode="file"
    else
        Enable_Fallback="false"
        # 由nginx处理了
        Enable_ProxyProtocol="false"
        Cert_Mode="none"
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
    # 暂时用不上
    if [[ "$rules_num" == "3" ]]; then
        echo
        echo -e "由XrayR管理ssl证书，注销Caddy申请证书功能"
        sed -i "s|tls |#tls |" ${caddy_config}
        systemctl restart caddy
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

    # 第一次默认安装acme
    if [[ ! -f "~/.acme.sh/acme.sh" ]]; then
        tls_acme_install
    else
        echo -e "acme已经在系统里了，跳过安装步骤..."
    fi
    tls_acme_obtain
}

install_Caddy() {
    # 官网选的集成插件下载链接，可用"caddy list-modules"命令查看
    caddy_bin="https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com/caddy-dns/cloudflare&p=github.com/caddy-dns/dnspod&p=github.com/mholt/caddy-l4"
    wget -N --no-check-certificate -O "/usr/bin/caddy" ${caddy_bin}
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
    caddy_systemd="/etc/systemd/system/caddy.service"
    wget -N --no-check-certificate -O ${caddy_systemd} ${caddy_service}
    sed -i "s|/etc/caddy/Caddyfile|${caddy_config}|g" ${caddy_systemd}
    systemctl enable caddy && systemctl daemon-reload
    echo
    echo -e "${green}Caddy2 安装完成${plain}"
}
install_web() {
    # 放个小游戏到/srv/www
    wget --no-check-certificate -O www.zip $web_2048
    unzip -o www.zip -d /srv/ && rm -f www.zip
}
config_caddy() {
    # keys：domain，port，tls，path/sni
    # caddy监控443和80，通过path分流到后端，所以后端服务不能设置这两个端口
    if [[ ! -d "/etc/caddy" ]]; then
        mkdir -p /etc/caddy
    fi
    cp -f ${caddy_config}{,_$(date +"%Y%m%d")}

    # Caddyfile格式
    cat >${caddy_config} <<EOF
${Domain_Srv} {
  "admin": {"disabled": true},
  "apps": {
    "layer4": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "routes": [
            {
              "match": [{"tls": {"sni": ["${Domain_Srv}"]}}],
              "handle": [
                {
                  "handler": "proxy",
                  "upstreams": [{"dial": ["${web_defalut}"]}]
                }
              ]
            }
          ]
        }
      }
    }
  }
}
EOF
    install_web
    systemctl restart caddy
}

config_caddy_Trojan() {
    echo "t"
}
config_caddy_Vmess() {
    echo "v"

}
config_caddy_Shadowsocks() {
    echo "s"

}

install_Nginx() {
    # nginx 安装预处理，只支持Debian
    $INS gnupg2 ca-certificates lsb-release debian-archive-keyring
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor |
        tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/debian $(lsb_release -cs) nginx" |
        tee /etc/apt/sources.list.d/nginx.list
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" |
        tee /etc/apt/sources.list.d/nginx.list

    apt -y update
    $INS nginx
    install_web
    sed -i "s|/usr/share/nginx/html|/srv/www|g" /etc/nginx/conf.d/default.conf
}

config_Nginx() {
    sed -i "s|worker_connections .*|worker_connections 1024;|" ${nginx_conf}
    sed -i "s|# multi_accept on;|multi_accept on;|" ${nginx_conf}
    snippet_map=$(sed -n "/map \$ssl_preread_server_name \$backend_name {/p" ${nginx_conf})
    if [[ -z ${snippet_map} ]]; then
        sed -i "/http {/ i \
        stream {\\n\
            map \$ssl_preread_server_name \$backend_name {\\n\
                default web;\\n\
            }\\n\
            upstream web {\\n\
                server 127.0.0.1:80;\\n\
            }\\n\
            server {\\n\
                listen 443 reuseport;\\n\
                listen [::]:443 reuseport;\\n\
                proxy_pass  \$backend_name;\\n\
                proxy_protocol on;\\n\
                ssl_preread on;\\n\
            }\\n\
        }\\n" ${nginx_conf}
    fi
}

config_Nginx_Trojan() {
    sed -i "/default web;/ i \
        ${Domain_SNI} trojan;" ${nginx_conf}

    # sed -i "/upstream web {/ i \
    # upstream proxy_trojan {\\n\
    #     server 127.0.0.1:10240;\\n\
    # }\\n" ${nginx_conf}
    # # 这里的 server 就是用来帮 Trojan 卸载代理协议的中间层
    # sed -i "/upstream web {/ i \
    #     server {\\n\
    #     listen 10240 proxy_protocol;\\n\
    #     proxy_pass  trojan;\\n\
    #     }\\n" ${nginx_conf}
    sed -i "/upstream web {/ i \
        upstream trojan {\\n\
        server 127.0.0.1:${inbound_port};\\n\
        }\\n" ${nginx_conf}
}

config_Nginx_Vmess() {
    sed -i "/default web;/ i ${Domain_SNI} vmess;" ${nginx_conf}
    sed -i "/upstream web {/ i \
        upstream vmess {\\n\
        server 127.0.0.1:${webserver_listen};\\n\
        }\\n" ${nginx_conf}
    config_Nginx_vhost
}
config_Nginx_Shadowsocks() {
    sed -i "/default web;/ i ${Domain_SNI} shadowsocks;" ${nginx_conf}
    sed -i "/upstream web {/ i \
        upstream shadowsocks {\\n\
        server 127.0.0.1:${webserver_listen};\\n\
        }\\n" ${nginx_conf}
    config_Nginx_vhost
}

config_Nginx_vhost() {
    # 生成落地站点配置
    vhost_file="/etc/nginx/conf.d/${Domain_SNI}.conf"
    cat >${vhost_file} <<EOF
server {
    # 开启 HTTP2 支持
    listen ${webserver_listen} ssl http2 proxy_protocol;
    server_name  ${Domain_SNI};
  
    gzip on;
    gzip_http_version 1.1;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_proxied any;
    gzip_types text/plain text/css application/json application/javascript application/x-javascript text/javascript;

    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_certificate      ${TLS_CertFile};
    ssl_certificate_key  ${TLS_KeyFile};
    ssl_session_cache    shared:SSL:1m;
    ssl_session_timeout  5m;
    ssl_ciphers          HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers  on;

    # WS 协议转发
    location ${network_path} {
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host       \$http_host;
        proxy_pass http://127.0.0.1:${inbound_port};
    }

    # 非标请求转发伪装
    location / {
       proxy_pass http://127.0.0.1:80;
    }
}
EOF
}

# https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
dns_update() {
    CF_TOKEN_DNS=${CF_Token}
    CFZONE_NAME=${Domain_Main}
    CFRECORD_NAME=${Domain_SNI}
    # If required settings are missing just exit
    if [ "$CF_TOKEN_DNS" = "" ]; then
        echo "Missing api-key, get at: https://www.cloudflare.com/a/account/my-account"
        echo "and save in ${0} or using the -k flag"
        exit 2
    fi
    if [ "$CFRECORD_NAME" = "" ]; then
        echo "Missing hostname, what host do you want to update?"
        echo "save in ${0} or using the -h flag"
        exit 2
    fi

    # Get zone_identifier & record_identifier
    CFZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$CFZONE_NAME" -H "Authorization: Bearer $CF_TOKEN_DNS" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)
    CFRECORD_ID_A=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records?type=A&name=$CFRECORD_NAME" -H "Authorization: Bearer $CF_TOKEN_DNS" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)
    CFRECORD_ID_AAAA=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records?type=AAAA&name=$CFRECORD_NAME" -H "Authorization: Bearer $CF_TOKEN_DNS" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)

    if [[ -n ${CFRECORD_ID_A} ]]; then
        curl -X DELETE "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/$CFRECORD_ID_A" \
            -H "Authorization: Bearer $CF_TOKEN_DNS" \
            -H "Content-Type: application/json"
    elif [[ -n ${CFRECORD_ID_AAAA} ]]; then
        curl -X DELETE "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/$CFRECORD_ID_AAAA" \
            -H "Authorization: Bearer $CF_TOKEN_DNS" \
            -H "Content-Type: application/json"
    fi

    wan_ip_v4=$(curl -s -4 ip.sb)
    wan_ip_v6=$(curl -s -6 ip.sb)

    if [[ -n ${wan_ip_v4} ]]; then
        echo "WanIP v4 is: ${wan_ip_v4}"
        RESPONSE_v4=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/" \
            -H "Authorization: Bearer $CF_TOKEN_DNS" \
            -H "Content-Type: application/json" \
            --data "{\"id\":\"$CFZONE_ID\",\"type\":\"A\",\"name\":\"$CFRECORD_NAME\",\"content\":\"$wan_ip_v4\", \"ttl\":60}")
    elif [[ -n ${wan_ip_v6} ]]; then
        echo "WanIP v6 is: ${wan_ip_v6}"
        RESPONSE_v6=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/" \
            -H "Authorization: Bearer $CF_TOKEN_DNS" \
            -H "Content-Type: application/json" \
            --data "{\"id\":\"$CFZONE_ID\",\"type\":\"AAAA\",\"name\":\"$CFRECORD_NAME\",\"content\":\"$wan_ip_v6\", \"ttl\":60}")
    else
        echo "There is no IP for this server, please check it"
    fi

    if [ "$RESPONSE_v4" != "${RESPONSE_v4%success*}" ] && [ "$(echo $RESPONSE_v4 | grep "\"success\":true")" != "" ]; then
        echo "Updated A Record succesfuly!"
    elif [ "$RESPONSE_v6" != "${RESPONSE_v6%success*}" ] && [ "$(echo $RESPONSE_v6 | grep "\"success\":true")" != "" ]; then
        echo "Updated AAAA Record succesfuly!"
    else
        echo 'Something went wrong :('
        echo "Response: $RESPONSE_v4"
        echo "Response: $RESPONSE_v6"
    fi
}

tls_acme_install() {
    echo -e "${green}开始安装 acme${plain}"
    curl https://get.acme.sh | sh
    echo -e "${green}acme 安装完成${plain}"
    # 开启自动升级
    source ~/.bashrc
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    tls_acme_register
}
tls_acme_register() {
    config_Email
    # https://github.com/acmesh-official/acme.sh/wiki/Server
    ~/.acme.sh/acme.sh --register-account -m ${Cert_Email} --server zerossl
    # ~/.acme.sh/acme.sh --set-default-ca  --server letsencrypt
}
tls_acme_obtain() {
    
    # 使用 acme.sh 生成证书
    if [[ -z ${CF_Token} ]]; then
        config_dns_Provider
    elif [[ -z ${Domain_SNI} ]]; then
        # Domain_SNI=$(cat ${config_ymlfile} | grep CertDomain: | awk -F "\"" 'NR==1{print $2}')
        read -p "请输入要申请证书的域名：" Domain_SNI
    fi

    # 自动解析域名
    dns_update

    if [[ ${Domain_SNI##*\.} =~ (cf|ga|gq|ml|tk) ]]; then
        echo "cloudflare不支持这些域名api方式管理：.cf, .ga, .gq, .ml, .tk"
        echo -e "不想折腾，垃圾域名还是扔了算了"
        # acme.sh --issue -d ${Domain_Srv} --standalone
    else
        echo "准备申请 ${Domain_SNI} 证书"
        sleep 3
        ~/.acme.sh/acme.sh --issue -d ${Domain_SNI} --dns ${dns_Provider_acme}
    fi
    tls_acme_deploy
}
tls_acme_deploy() {
    if [ ! -d "${tls_path}" ]; then
        mkdir -p ${tls_path}
    fi
    if [[ -z ${TLS_CertFile} ]]; then
        TLS_CertFile="${tls_path}/${Domain_SNI}.crt"
        TLS_KeyFile="${tls_path}/${Domain_SNI}.key"
    fi
    ~/.acme.sh/acme.sh --install-cert -d ${Domain_SNI} \
        --fullchain-file ${TLS_CertFile} \
        --key-file ${TLS_KeyFile} \
        --reloadcmd "systemctl restart nginx; systemctl restart caddy"

    # 加个保险每2个月定时自动部署一次，防止acme自动更新未部署到 $tls_path
    sed -i '/^.*${Domain_SNI}.*/d' /etc/crontab
    echo -e "0 0 1 */2 * ~/.acme.sh/acme.sh --install-cert -d ${Domain_SNI} --fullchain-file ${TLS_CertFile} --key-file ${TLS_KeyFile}" >>/etc/crontab
    systemctl restart ${cron_srv}
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

install_XrayR() {
    echo
    echo -e "${green}准备安装 XrayR${plain}"
    if [[ -e /usr/local/XrayR/ ]]; then
        rm -rf /usr/local/XrayR/
    fi

    mkdir -p /usr/local/XrayR/
    cd /usr/local/XrayR/

    latest_version=$(curl -Ls "https://api.github.com/repos/newxrayr/XrayR/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "${latest_version}" ]]; then
        latest_version="获取在线版本失败，请检查网络连接"
        exit 1
    fi
    echo
    read -p "输入要安装版本（默认：${latest_version}）:" XrayR_version
    [ -z "${XrayR_version}" ] && XrayR_version="${latest_version}"

    echo
    echo -e "开始安装 XrayR 版本：${XrayR_version}"
    XrayR_url="https://github.com/newxrayr/XrayR/releases/download/${XrayR_version}/XrayR-linux-64.zip"
    wget -N --no-check-certificate -O /usr/local/XrayR/XrayR-linux-64.zip ${XrayR_url}
    if [[ $? -ne 0 ]]; then
        echo -e "${red}下载 XrayR ${XrayR_version} 失败，请确保此版本存在且服务器能够下载 Github 文件${plain}"
        exit 1
    fi

    unzip XrayR-linux-64.zip
    rm -f XrayR-linux-64.zip
    chmod +x XrayR
    rm -f /etc/systemd/system/XrayR.service
    file="https://github.com/cdnf/XrayR-release/raw/master/XrayR.service"
    wget -N --no-check-certificate -O /etc/systemd/system/XrayR.service ${file}
    systemctl daemon-reload && systemctl stop XrayR
    systemctl enable XrayR
    echo -e "${green}XrayR ${XrayR_version}${plain} 安装完成，已设置开机自启"
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
        echo -e "全新安装完成，更多内容请见：https://crackair.gitbook.io/xrayr-project/"
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
            echo -e "${red}XrayR 可能启动失败，请稍后使用 XrayR log 查看日志信息，若无法启动，则可能更改了配置格式，请前往 wiki 查看：https://crackair.gitbook.io/xrayr-project/${plain}"
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
        curl -o /usr/bin/XrayR -Ls https://raw.githubusercontent.com/cdnf/XrayR-release/master/XrayR.sh
        chmod +x /usr/bin/XrayR
    fi
}

# 菜单
menu() {
    echo
    echo -e "======================================"
    echo -e "	Author: 金将军"
    echo -e "	Version: 3.1.0"
    echo -e "======================================"
    echo
    echo -e "\t1.安装XrayR"
    echo -e "\t2.新增nodes"
    echo -e "\t3.使用acme更新证书"
    echo -e "\t4.开启系统Swap"
    echo -e "\t9.卸载XrayR"
    echo -e "\t0.退出\n"
    echo
    read -ep "请输入数字选项: " menu_Num
}
while [ 1 ]; do
    menu
    case "$menu_Num" in
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
        tls_acme_obtain
        ;;
    4)
        get_Swap
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
