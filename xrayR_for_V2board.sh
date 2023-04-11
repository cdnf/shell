#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)
config_XrayR="/etc/XrayR/config.yml"
config_rulefile="/etc/XrayR/rulelist"
config_dnsfile="/etc/XrayR/dns.json"
caddy_config="/etc/caddy/Caddyfile"
tls_path="/srv/.cert"
web_2048="https://github.com/cdnf/shell/raw/master/resource/www.zip"
# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用root用户运行此脚本！\n" && exit 1

# 安装基础依赖
local_tool="wget curl git unzip gzip tar screen lrzsz socat ntpdate jq cron dnsutils net-tools file"
if [[ -f /usr/bin/apt && -f /bin/systemctl ]]; then
    os="debian"
    cron_srv="cron"
    INS="apt -y install"
    apt -y update
    apt remove -y httpd
    $INS ${local_tool}
else
    echo -e "${red}未检测到系统版本，本垃圾程序只支持Debian！，如果检测有误，请联系作者${plain}\n" && exit 1
fi
sys_bit=$(uname -m)
if [[ ${sys_bit} != "x86_64" ]]; then
    echo "本软件不支持 32 位系统(x86)，请使用 64 位系统(x86_64)，如果检测有误，请联系作者"
    exit 2
fi
#设置时区为东八区
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
# 开启cron日志输出
sed -i "/${cron_srv}/s/^#//" /etc/rsyslog.conf
systemctl restart rsyslog
#添加系统定时任务自动同步时间并把写入到BIOS，重启定时任务服务
ntpdate cn.pool.ntp.org && hwclock -w
sed -i '/^.*ntpdate*/d' /etc/crontab
sed -i '$a\0 * * * * root ntpdate cn.pool.ntp.org && hwclock -w >> /dev/null 2>&1' /etc/crontab
systemctl restart ${cron_srv}

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
    cat >${config_XrayR} <<EOF
Log:
  Level: error # Log level: none, error, warning, info, debug 
  AccessPath: # /etc/XrayR/access.Log
  ErrorPath: # /etc/XrayR/error.log
DnsConfigPath: # /etc/XrayR/dns.json # Path to dns config, check https://xtls.github.io/config/dns.html for help
RouteConfigPath: # /etc/XrayR/route.json # Path to route config, check https://xtls.github.io/config/routing.html for help
InboundConfigPath: # /etc/XrayR/custom_inbound.json # Path to custom inbound config, check https://xtls.github.io/config/inbound.html for help
OutboundConfigPath: # /etc/XrayR/custom_outbound.json # Path to custom outbound config, check https://xtls.github.io/config/outbound.html for help
ConnectionConfig:
  Handshake: 4 # Handshake time limit, Second
  ConnIdle: 30 # Connection idle time limit, Second
  UplinkOnly: 2 # Time limit when the connection downstream is closed, Second
  DownlinkOnly: 4 # Time limit when the connection is closed after the uplink is closed, Second
  BufferSize: 64 # The internal cache size of each connection, kB
Nodes:
EOF
    echo -e "基础配置已写入 ${green}${config_XrayR}${plain}"
}
config_nodes() {
    if [[ ! -f ${config_XrayR} ]]; then
        echo "配置文件不存在，请确认已安装XrayR"
        exit 1
    else
        cat >>${config_XrayR} <<EOF
    -
        PanelType: "NewV2board" # Panel type: SSpanel, V2board, NewV2board, PMpanel, Proxypanel, V2RaySocks
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
            RuleListPath: # /etc/XrayR/rulelist Path to local rulelist file
        ControllerConfig:
            ListenIP: 0.0.0.0 # IP address you want to listen
            SendIP: 0.0.0.0 # IP address you want to send pacakage
            UpdatePeriodic: 60 # Time to update the nodeinfo, how many sec.
            EnableDNS: false # Use custom DNS config, Please ensure that you set the dns.json well
            DNSType: AsIs # AsIs, UseIP, UseIPv4, UseIPv6, DNS strategy
            EnableProxyProtocol: ${Enable_ProxyProtocol} # Only works for WebSocket and TCP
            AutoSpeedLimitConfig:
                Limit: 0 # Warned speed. Set to 0 to disable AutoSpeedLimit (mbps)
                WarnTimes: 0 # After (WarnTimes) consecutive warnings, the user will be limited. Set to 0 to punish overspeed user immediately.
                LimitSpeed: 0 # The speedlimit of a limited user (unit: mbps)
                LimitDuration: 0 # How many minutes will the limiting last (unit: minute)
            GlobalDeviceLimitConfig:
                Enable: false # Enable the global device limit of a user
                RedisAddr: 127.0.0.1:6379 # The redis server address
                RedisPassword: ${Redis_Password} # Redis password
                RedisDB: 0 # Redis DB
                Timeout: 5 # Timeout for redis request
                Expiry: 60 # Expiry time (second)
            EnableFallback: ${Enable_Fallback} # Only support for Trojan and Vless
            FallBackConfigs: # Support multiple fallbacks
                -
                    SNI: # TLS SNI(Server Name Indication), Empty for any
                    Alpn: # Alpn, Empty for any
                    Path: # HTTP PATH, Empty for any
                    Dest: "80" # Required, Destination of fallback, check https://xtls.github.io/config/features/fallback.html for details.
                    ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for disable
EOF
        echo -e "节点配置已写入 ${green}${config_XrayR}${plain}"
    fi
}
config_Cert() {
    cat >>${config_XrayR} <<EOF
            CertConfig:
                CertMode: "${Cert_Mode}" # Option about how to get certificate: none, file, http, tls, dns. Choose "none" will forcedly disable the tls config.
                CertDomain: "${network_domain}" # Domain to cert
                CertFile: "${TLS_CertFile}" # Provided if the CertMode is file
                KeyFile: "${TLS_KeyFile}" # http default in /etc/XrayR/cert/certificates/
                Email: "${Cert_Email}"
EOF

    if [[ ${dns_Provider} == "dnspod" ]]; then
        config_Provider_dnspod
    elif [[ ${dns_Provider} == "cloudflare" ]]; then
        config_Provider_cloudflare
    fi
}
config_Provider_dnspod() {
    cat >>${config_XrayR} <<EOF
                Provider: "dnspod" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    DNSPOD_API_KEY: "${SECRET_KEY}"
EOF
}
config_Provider_cloudflare() {
    cat >>${config_XrayR} <<EOF
                Provider: "cloudflare" # DNS cert provider: alidns, cloudflare, dnspod, namesilo. Get the full support list here: https://go-acme.github.io/lego/dns/
                DNSEnv: # DNS ENV option used by DNS provider
                    # CF_API_EMAIL: "${CF_USER}"
                    # CF_API_KEY: "${SECRET_KEY}"
                    CF_DNS_API_TOKEN: "${SECRET_KEY}"
EOF
}

config_XrayR_dns() {
    cat >${config_dnsfile} <<EOF
{
    "servers": [
        "1.1.1.1",
        "1.2.4.8",
        "8.8.8.8",
        "localhost"
    ],
    "tag": "dns_inbound"
}
EOF
}
# 生成邮箱账号
config_Email() {
    # local Cert_Email_Account=$(((RANDOM << 9)))
    # Cert_Email=${Cert_Email_Account}@gmail.com
    # 默认为二级子域名，${Domain_Srv#*\.} 取域名中第一个”.“右侧到结尾字符串
    Cert_Email=admin@${network_domain#*\.}
}

config_GetNodeInfo() {
    NodeInfo_API="${Api_Host}/api/v1/server/UniProxy/config?token=${Api_Key}&node_type=${Node_Type,,}&node_id=${Node_ID}"
    NodeInfo_json=$(curl -s "${NodeInfo_API}" | jq .)
    
    if [[ "${Node_Type}" == "V2ray" ]]; then
        # 后端监听端口
        inbound_port=$(echo ${NodeInfo_json} | jq -r '.server_port')
        # 加密方式：tls: 1 启用，不启用时怎么处理？
        network_security=$(echo ${NodeInfo_json} | jq -r '.tls')
        if [[ "${network_security}" == "1" ]]; then
            network_security="tls"
        fi
        # 传输协议：tcp|grpc|ws才对接caddy
        network_protocol=$(echo ${NodeInfo_json} | jq -r '.network')
        # 伪装serverName
        network_sni=$(echo ${NodeInfo_json} | jq -r '.networkSettings.headers.Host')
        # 分流路径，回落对接用
        network_path=$(echo ${NodeInfo_json} | jq -r '.networkSettings.path')
        # 配合自动解析，懒得指定连接域名，强制约定配置伪装serverName为连接域名
        network_domain=${network_sni}
    elif [[ "${Node_Type}" == "Trojan" ]]; then
        # 后端监听端口
        inbound_port=$(echo ${NodeInfo_json} | jq -r '.server_port')
        # 加密方式：tls|xtls|none，Trojan强制tls
        network_security="tls"
        # 传输协议：tcp|grpc|ws才对接caddy,v2board默认只有tcp
        network_protocol="tcp"
        # 伪装serverName，回落对接用
        network_sni=$(echo ${NodeInfo_json} | jq -r '.server_name')
        # 配合自动解析，懒得指定连接域名，Trojan节点提供了连接域名
        network_domain=$(echo ${NodeInfo_json} | jq -r '.host')
    elif [[ "${Node_Type}" == "Shadowsocks" ]]; then
        # 后端监听端口
        inbound_port=$(echo ${NodeInfo_json} | jq -r '.server_port')
        # 加密算法
        network_security=$(echo ${NodeInfo_json} | jq -r '.cipher')
        # 混淆方式
        network_protocol=$(echo ${NodeInfo_json} | jq -r '.obfs')
        # 混淆serverName
        network_sni=$(echo ${NodeInfo_json} | jq -r '.obfs_settings.host')
        # 分流路径，回落对接用，没有接口，直接写死
        network_path=$(echo ${NodeInfo_json} | jq -r '.obfs_settings.path')
        # 配合自动解析，懒得指定连接域名，强制约定混淆伪装域名即为连接域名
        network_domain=${network_sni}
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

install_Caddy() {
    $INS debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt update
    $INS caddy && systemctl stop caddy

    # 集成插件下载链接，可用"caddy list-modules"命令查看
    github_user="lxhao61"
    github_repo="integrated-examples"
    github_file="caddy-linux-amd64.tar.gz"
    github_latest
    # caddy_url="https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com/caddy-dns/cloudflare&p=github.com/caddy-dns/dnspod&p=github.com/mholt/caddy-l4"
    caddy_url="https://github.com/${github_user}/${github_repo}/releases/download/${latest_version}/${github_file}"

    
    # wget -N --no-check-certificate -O caddy ${caddy_url}
    wget -N --no-check-certificate -O caddy.tar.gz ${caddy_url}
    tar zxvf caddy.tar.gz caddy && rm -f caddy.tar.gz
    mv /usr/bin/caddy{,.bak} && mv -f caddy "/usr/bin/caddy" && chmod +x "/usr/bin/caddy"
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
    caddy_config_path=$(echo ${caddy_config%/*})
    if [[ ! -d ${caddy_config_path} ]]; then
        mkdir -p ${caddy_config_path}
    fi
    # 修改caddy服务指定的配置文件
    cp -f ${caddy_config}{,_$(date +"%Y%m%d")}
    # sed -i "s|^ExecStart.*|ExecStart=/usr/bin/caddy run --environ --config ${caddy_config}|" "/lib/systemd/system/caddy.service"
    # sed -i "s|^ExecReload.*|ExecReload=/usr/bin/caddy reload --force --config ${caddy_config}|" "/lib/systemd/system/caddy.service"
    # rm -f /etc/caddy/Caddyfile

    # Caddyfile格式
    cat >${caddy_config} <<EOF
${network_domain} {
    root * /srv/www
    file_server
    log {
        output file /var/log/caddy/access.log
    }
    tls ${Cert_Email}
    @mywebsocket {
        path ${network_path}
        header Connection *Upgrade*
        header Upgrade websocket
    }
    reverse_proxy @mywebsocket localhost:${inbound_port}
}
EOF
    install_web
    systemctl daemon-reload && systemctl restart caddy
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

# https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
dns_update() {
    CFZONE_NAME=${network_domain#*\.}
    CFRECORD_NAME=${network_domain}
    # If required settings are missing just exit
    if [[ -z ${CF_TOKEN_DNS} ]]; then
        echo "Missing api-key, get at: https://www.cloudflare.com/a/account/my-account"
        echo "and save in ${0} or using the -k flag"
        exit 2
    fi
    if [[ -z ${CFRECORD_NAME} ]]; then
        echo "Missing hostname, what host do you want to update?"
        echo "save in ${0} or using the -h flag"
        exit 2
    fi

    # Get zone_identifier & record_identifier
    CFZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${CFZONE_NAME}" -H "Authorization: Bearer ${CF_TOKEN_DNS}" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)
    CFRECORD_ID_A=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records?type=A&name=${CFRECORD_NAME}" -H "Authorization: Bearer ${CF_TOKEN_DNS}" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)
    CFRECORD_ID_AAAA=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records?type=AAAA&name=${CFRECORD_NAME}" -H "Authorization: Bearer ${CF_TOKEN_DNS}" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)

    if [[ -n ${CFRECORD_ID_A} ]]; then
        curl -X DELETE "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records/${CFRECORD_ID_A}" \
            -H "Authorization: Bearer ${CF_TOKEN_DNS}" \
            -H "Content-Type: application/json"
    fi
    if [[ -n ${CFRECORD_ID_AAAA} ]]; then
        curl -X DELETE "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records/${CFRECORD_ID_AAAA}" \
            -H "Authorization: Bearer ${CF_TOKEN_DNS}" \
            -H "Content-Type: application/json"
    fi

    wan_ip_v4=$(curl -s -4 ip.sb)
    wan_ip_v6=$(curl -s -6 ip.sb)

    if [[ -n ${wan_ip_v4} ]]; then
        echo "WanIP v4 is: ${wan_ip_v4}"
        RESPONSE_v4=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records/" \
            -H "Authorization: Bearer ${CF_TOKEN_DNS}" \
            -H "Content-Type: application/json" \
            --data "{\"id\":\"${CFZONE_ID}\",\"type\":\"A\",\"name\":\"${CFRECORD_NAME}\",\"content\":\"$wan_ip_v4\", \"ttl\":60}")
        if [ "${RESPONSE_v4}" != "${RESPONSE_v4%success*}" ] && [ "$(echo ${RESPONSE_v4} | grep "\"success\":true")" != "" ]; then
            echo "Updated A Record succesfuly!"
        else
            echo 'Something went wrong :('
            echo "Response: ${RESPONSE_v4}"
        fi
    else
        echo "There is no IPV4 for this server, please check it"
    fi
    if [[ -n ${wan_ip_v6} ]]; then
        echo "WanIP v6 is: ${wan_ip_v6}"
        RESPONSE_v6=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records/" \
            -H "Authorization: Bearer ${CF_TOKEN_DNS}" \
            -H "Content-Type: application/json" \
            --data "{\"id\":\"${CFZONE_ID}\",\"type\":\"AAAA\",\"name\":\"${CFRECORD_NAME}\",\"content\":\"$wan_ip_v6\", \"ttl\":60}")
        if [ "${RESPONSE_v6}" != "${RESPONSE_v6%success*}" ] && [ "$(echo ${RESPONSE_v6} | grep "\"success\":true")" != "" ]; then
            echo "Updated AAAA Record succesfuly!"
        else
            echo 'Something went wrong :('
            echo "Response: ${RESPONSE_v6}"
        fi
    else
        echo "There is no IPV6 for this server, please check it"
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

github_latest() {
    github_api="https://api.github.com/repos/${github_user}/${github_repo}/releases/latest"
    latest_version=$(curl -Ls "${github_api}" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "${latest_version}" ]]; then
        echo
        echo -e "获取在线版本失败，请检查网络连接"
        exit 1
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

    github_user="XrayR-project"
    github_repo="XrayR"
    github_file="XrayR-linux-64.zip"
    # latest_version=$(curl -Ls "https://api.github.com/repos/XrayR-project/XrayR/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    github_latest

    echo
    read -p "输入要安装版本（默认：${latest_version}）:" XrayR_version
    [ -z "${XrayR_version}" ] && XrayR_version="${latest_version}"

    echo
    echo -e "开始安装 XrayR 版本：${XrayR_version}"
    XrayR_url="https://github.com/${github_user}/${github_repo}/releases/download/${XrayR_version}/${github_file}"
    wget -N --no-check-certificate -O /usr/local/XrayR/XrayR-linux-64.zip ${XrayR_url}
    if [[ $? -ne 0 ]]; then
        echo -e "${red}下载 XrayR ${XrayR_version} 失败，请确保此版本存在且服务器能够下载 Github 文件${plain}"
        exit 1
    fi

    unzip XrayR-linux-64.zip && rm -f XrayR-linux-64.zip
    chmod +x XrayR
    XrayR_service="https://github.com/XrayR-project/XrayR-release/raw/master/XrayR.service"
    wget -N --no-check-certificate -O /etc/systemd/system/XrayR.service ${XrayR_service}
    systemctl daemon-reload && systemctl stop XrayR
    systemctl enable XrayR
    echo -e "${green}XrayR ${XrayR_version}${plain} 安装完成，已设置开机自启"
    mkdir -p /etc/XrayR/
    cp geoip.dat /etc/XrayR/
    cp geosite.dat /etc/XrayR/

    if [[ ! -f /etc/XrayR/dns.json ]]; then
        config_XrayR_dns
    fi
    if [[ ! -f /etc/XrayR/route.json ]]; then
        cp route.json /etc/XrayR/
    fi
    # if [[ ! -f /etc/XrayR/custom_outbound.json ]]; then
    #     cp custom_outbound.json /etc/XrayR/
    # fi
    # if [[ ! -f /etc/XrayR/custom_inbound.json ]]; then
    #     cp custom_inbound.json /etc/XrayR/
    # fi
    # if [[ ! -f /etc/XrayR/rulelist ]]; then
    #     cp rulelist /etc/XrayR/
    # fi
    if [[ ! -f ${config_XrayR} ]]; then
        config_set
        config_init && config_nodes
        config_Cert
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
            echo -e "${red}XrayR 可能启动失败，请稍后使用 XrayR log 查看日志信息，若无法启动，${plain}"
            echo -e "${red}则可能更改了配置格式，请前往 wiki 查看：https://crackair.gitbook.io/xrayr-project/${plain}"
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
        curl -o /usr/bin/XrayR -Ls https://github.com/XrayR-project/XrayR-release/raw/master/XrayR.sh
        chmod +x /usr/bin/XrayR
    fi
}

# Pre-installation settings
config_set() {
    if [[ -z ${Api_Key} ]]; then
        read -p "前端面板认证域名（包括http[s]://）：" Api_Host
        read -p "前端面板的apikey：" Api_Key
    fi

    read -p "面板里的节点ID：" Node_ID
    [ -z "${Node_ID}" ] && Node_ID=1

    echo -e "[1] V2ray \t [2] Trojan \t [3] Shadowsocks"
    read -p "节点类型（默认V2ray）：" node_num
    [ -z "${node_num}" ] && node_num="1"
    if [[ "$node_num" == "1" ]]; then
        Node_Type="V2ray"
    elif [[ "$node_num" == "2" ]]; then
        Node_Type="Trojan"
    elif [[ "$node_num" == "3" ]]; then
        Node_Type="Shadowsocks"
    else
        echo "type error, please try again"
        pause_press
        config_set
    fi

    # 通过cloudflare解析域名，不支持cf，ml，tk，gq等烂大街的免费域名
    # CF_Token=$(cat ~/.acme.sh/account.conf | grep SAVED_CF_Token= | awk -F "'" '{print $2}')
    read -p "CloudFlare域名管理Token：" CF_TOKEN_DNS

    # 从面板获取节点关键信息
    config_GetNodeInfo
    if [[ ${inbound_port} == "443" || ${inbound_port} == "80" ]]; then
        echo "后端服务不可设置为 443 或 80，请到面板修改为其他端口"
        pause_press
        config_set
    fi
    # 证书相关信息
    config_Email
    TLS_CertFile="${tls_path}/${network_domain}.crt"
    TLS_KeyFile="${tls_path}/${network_domain}.key"

    echo
    echo -e "\t面板类型：${green}V2bord${plain}"
    echo -e "\t节点类型：${green}${Node_Type}${plain}"
    echo -e "\t节点ID：${green}${Node_ID}${plain}"
    echo -e "\t连接地址：${green}${network_domain}${plain}"
    echo -e "\t后端监听端口：${green}${inbound_port}${plain}"
    echo -e "\t传输协议：${green}${network_protocol}${plain}"
    echo -e "\t加密方式：${green}${network_security}${plain}"
    if [[ "${Node_Type}" == "Trojan" ]]; then
        echo -e "\t伪装域名「serverName」：${green}${network_sni}${plain}"
    fi
    if [[ "${Node_Type}" == "V2ray" ]]; then
        echo -e "\t分流路径「path」：${green}${network_path}${plain}"
        echo -e "\t伪装域名「serverName」：${green}${network_sni}${plain}"
    fi
    if [[ "${Node_Type}" == "Shadowsocks" ]]; then
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
    echo -e "2. XrayR"
    echo -e "本脚本默认Caddy前置，要其他组合请后续自行修改配置"
    echo -e "========================================================="
    read -p "请选择方案组合（默认 1）：" rules_num
    [ -z "${rules_num}" ] && rules_num="1"

    if [[ "$rules_num" == "1" ]]; then
        systemctl disable nginx; systemctl stop nginx
        # 由caddy管理证书
        Cert_Mode="none"

        install_Caddy && config_caddy
        # 未完待续
        # if [[ "${Node_Type}" == "Trojan" ]]; then
        #     config_caddy_Trojan
        # fi
        # if [[ "${Node_Type}" == "V2ray" ]]; then
        #     config_caddy_Vmess
        # fi
        # if [[ "${Node_Type}" == "Shadowsocks" ]]; then
        #     config_caddy_Shadowsocks
        # fi
        systemctl restart caddy
    elif [[ "$rules_num" == "2" ]]; then
        systemctl disable caddy; systemctl stop caddy
        read -p "请选择证书申请模式：[1]http \t [2]dns \t [3]none" Cert_Mode
            case "${Cert_Mode}" in
            1)
                Cert_Mode="http"
                ;;
            2)
                Cert_Mode="dns"
                read -p "请选择DNS托管商：[1]dnspod \t [2]cloudflare" dns_Provider
                    case "${dns_Provider}" in
                    1)
                        dns_Provider="dnspod"
                        read -p "请输入「DNSPOD_API_KEY」" SECRET_KEY
                        ;;
                    2)
                        dns_Provider="cloudflare"
                        read -p "请输入「CF_DNS_API_TOKEN」" SECRET_KEY
                        ;;
                    *)
                    echo -e "无法识别指令，请输入正确的数字"
                    ;;
                    esac
               ;;
            3)
                Cert_Mode="none"
                ;;
            *)
            echo -e "无法识别指令，请输入正确的数字"
            ;;
            esac
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

    if [[ "${Node_Type}" == "Trojan" ]]; then
        Enable_Fallback="true"
        # V2board里Trojan无法配置路径分流
        Enable_ProxyProtocol="true"
    else
        Enable_Fallback="false"
        # 由caddy/nginx处理了
        Enable_ProxyProtocol="false"
    fi

    # 偷懒自动解析域名，只支持cloudflare
    dns_update
}

# 菜单
menu() {
    echo
    echo -e "======================================"
    echo -e "	Author: 金三将军"
    echo -e "	Version: 4.0.5"
    echo -e "======================================"
    echo
    echo -e "\t1.安装XrayR"
    echo -e "\t2.新增nodes"
    echo -e "\t3.开启系统Swap"
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
        config_nodes && config_Cert
        XrayR restart && XrayR log
        ;;
    3)
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

# TODO
# 自动获取节点对外连接端口，并自动同步caddy配置
# 服务端定期更换对外连接端口为随机值