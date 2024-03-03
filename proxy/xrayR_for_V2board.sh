#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

export LC_ALL=C
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8

cur_dir=$(pwd)
resource="https://github.com/cdnf/shell/raw/master/resource"
config_XrayR="/etc/XrayR/config.yml"
config_rulefile="/etc/XrayR/rulelist"
config_dnsfile="/etc/XrayR/dns.json"
caddy_config="/etc/caddy/Caddyfile.json"
# 若域名为 x.y，那么从 Let's Encrypt 申请的普通 TLS 证书在 ‘${root}/certificates/acme-v02.api.letsencrypt.org-directory/x.y’ 目录中
# 若域名为 x.y，那么从 ZeroSSL 申请的普通 TLS 证书在 ‘${root}/certificates/acme.zerossl.com-v2-dv90/x.y’ 目录中
tls_path="/var/tls" # caddy 存放 TLS 证书的基本路径
tls_module="acme" #acme=从 Let's Encrypt 申请 TLS 证书，zerossl=从 ZeroSSL 申请 TLS 证书
port_http1=8080 # HTTP/1.1 server 及 H2C server 本地监听端口
port_http2=8443 # HTTP/2 server 本地监听端口

# fonts color
red() {
    echo -e "\033[31m\033[01m$1\033[0m"
}
green() {
    echo -e "\033[32m\033[01m$1\033[0m"
}
yellow() {
    echo -e "\033[33m\033[01m$1\033[0m"
}
blue() {
    echo -e "\033[34m\033[01m$1\033[0m"
}
bold() {
    echo -e "\033[1m\033[01m$1\033[0m"
}

# check root
[[ $EUID -ne 0 ]] && red "错误：必须使用root用户运行此脚本！\n" && exit 1

# 安装基础依赖
local_tool="wget curl git unzip gzip tar screen lrzsz socat jq cron dnsutils net-tools file ntpdate systemd-timesyncd"
if [[ -f /usr/bin/apt && -f /bin/systemctl ]]; then
    os="debian"
    cron_srv="cron"
    INS="apt -y install"
    apt -y update
    $INS ${local_tool}
else
    red "未检测到系统版本，本垃圾程序只支持Debian！如果检测有误，请联系作者\n" && exit 1
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
# ntpdate cn.pool.ntp.org && hwclock -w
# sed -i '/^.*ntpdate*/d' /etc/crontab
# sed -i '$a\0 * * * * root ntpdate cn.pool.ntp.org && hwclock -w >> /dev/null 2>&1' /etc/crontab
# systemctl restart ${cron_srv}

# 启用 ll 命令方便后续使用
# sed -i "s|^# export LS_OPTIONS|export LS_OPTIONS|" ~/.bashrc
# sed -i "s|^# eval |eval |" ~/.bashrc
# sed -i "s|^# alias l|alias l|g" ~/.bashrc
# source ~/.bashrc

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
# 简单粗暴判断，无容错功能，故8443和443会认为有冲突
# contains aList anItem
# echo $? # 0： match, 1: failed
contains () {
    aList=$1
    anItem=$2
    amsg=$(echo ${aList} | grep ${anItem})
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
    green "基础配置已写入 ${config_XrayR}"
}
config_nodes() {
    if [[ ${Node_Type} == "Vmess" || ${Node_Type} == "V2ray" ]]; then
        XNode_Type="V2ray"
    else
        XNode_Type=${Node_Type}
    fi

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
            NodeType: "${XNode_Type}" # Node type: V2ray, Trojan, Shadowsocks, Shadowsocks-Plugin
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
            DisableUploadTraffic: false # Disable Upload Traffic to the panel
            DisableGetRule: false # Disable Get Rule from the panel
            DisableIVCheck: false # Disable the anti-reply protection for Shadowsocks
            DisableSniffing: false # Disable domain sniffing 
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
                    Dest: "${port_http1}" # Required, Destination of fallback, check https://xtls.github.io/config/features/fallback.html for details.
                    ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for disable
EOF
        green "节点配置已写入 ${config_XrayR}"
    fi
}
config_Cert() {
    cat >>${config_XrayR} <<EOF
            CertConfig:
                RejectUnknownSni: false # Reject unknown SNI
                CertMode: "${Cert_Mode}" # Option about how to get certificate: none, file, http, tls, dns. Choose "none" will forcedly disable the tls config.
                CertDomain: "${network_host}" # Domain to cert
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
    Cert_Email=admin@${network_host#*\.}
}
# 申请TLS证书
config_TLS() {
    # 使用caddy申请的证书相关信息
    config_Email
    
    if [[ "${tls_module}" == "acme" ]]; then
        tls_module_path="certificates/acme-v02.api.letsencrypt.org-directory"
    elif [[ "${tls_module}" == "zerossl" ]]; then
        tls_module_path="certificates/acme.zerossl.com-v2-dv90"
    fi
    TLS_CertFile="${tls_path}/${tls_module_path}/${network_host}/${network_host}.crt"
    TLS_KeyFile="${tls_path}/${tls_module_path}/${network_host}/${network_host}.key"

}

config_GetNodeInfo() {
    NodeInfo_API="${Api_Host}/api/v1/server/UniProxy/config?token=${Api_Key}&node_type=${Node_Type,,}&node_id=${Node_ID}"
    NodeInfo_json=$(curl -s "${NodeInfo_API}" | jq .)
    
    # 公共参数
    # 对外连接域名，需接口增加 host 字段输出
    network_host=$(echo ${NodeInfo_json} | jq -r '.host')
    # 对外连接端口，需接口增加 port 字段输出
    network_port=$(echo ${NodeInfo_json} | jq -r '.port')
    # 后端监听端口
    server_port=$(echo ${NodeInfo_json} | jq -r '.server_port')

    if [[ "${Node_Type}" == "Trojan" ]]; then
        # 加密方式：tls|xtls|none，Trojan强制tls
        network_security="tls"
        # 传输协议：tcp|grpc|ws才对接caddy,v2board默认只有tcp
        network_protocol="tcp"
        # 伪装serverName，回落对接用
        network_sni=$(echo ${NodeInfo_json} | jq -r '.server_name')
    elif [[ "${Node_Type}" == "Vmess" || "${Node_Type}" == "V2ray" ]]; then
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
    elif [[ "${Node_Type}" == "Shadowsocks" ]]; then
        # 加密算法
        network_security=$(echo ${NodeInfo_json} | jq -r '.cipher')
        # 混淆方式
        network_protocol=$(echo ${NodeInfo_json} | jq -r '.obfs')
        # 混淆serverName
        network_sni=$(echo ${NodeInfo_json} | jq -r '.obfs_settings.host')
        # 分流路径，回落对接用，没有接口，直接写死
        network_path=$(echo ${NodeInfo_json} | jq -r '.obfs_settings.path')
    else
        yellow "未知节点类型，或者接口不通，请检查……"
        pause_press
        config_set
    fi
    if [[ -z ${NodeInfo_json} ]]; then
        echo "接口获取数据失败，请确保api地址畅通且授权正确"
        pause_press
        config_set
    fi
    if [[ -z ${network_sni} ]]; then
       network_sni=${network_host}
    fi
    
    echo
    green "从 ${Api_Host} 获取 ${Node_ID} 号 ${Node_Type} 节点信息完成"
}

install_Caddy() {
    # 安装caddy前先禁用其他网站程序
    systemctl disable nginx; systemctl stop nginx
    systemctl disable httpd; systemctl stop httpd
    systemctl disable apache2; systemctl stop apache2

    $INS debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt update
    $INS caddy && systemctl stop caddy

    # 集成插件下载链接，可用"caddy list-modules"命令查看
    github_user="lxhao61"
    github_repo="integrated-examples"
    github_file="caddy-linux-amd64.tar.gz"
    
    # GET latest_version
    github_latest

    caddy_url="https://github.com/${github_user}/${github_repo}/releases/download/${latest_version}/${github_file}"
    # Specify version
    # caddy_url="https://github.com/${github_user}/${github_repo}/releases/download/20230412/${github_file}"
    # offical from caddyserver
    # caddy_url="https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com/caddy-dns/cloudflare&p=github.com/caddy-dns/dnspod&p=github.com/mholt/caddy-l4"

    
    # wget -N --no-check-certificate -O caddy ${caddy_url}
    wget -N --no-check-certificate -O caddy.tar.gz ${caddy_url}
    tar zxvf caddy.tar.gz caddy && rm -f caddy.tar.gz
    mv /usr/bin/caddy{,.bak} && mv -f caddy "/usr/bin/caddy" && chmod +x "/usr/bin/caddy"

    install_web

    # keys：domain，port，tls，path/sni
    caddy_config_path=$(echo ${caddy_config%/*})
    if [[ ! -d ${caddy_config_path} ]]; then
        mkdir -p ${caddy_config_path}
    fi
    # 修改caddy服务指定的配置文件
    cp -f ${caddy_config}{,_$(date +"%Y%m%d")}
    sed -i "s|^ExecStart.*|ExecStart=/usr/bin/caddy run --environ --config ${caddy_config}|" "/lib/systemd/system/caddy.service"
    sed -i "s|^ExecReload.*|ExecReload=/usr/bin/caddy reload --force --config ${caddy_config}|" "/lib/systemd/system/caddy.service"
    systemctl daemon-reload

    green "Caddy2 安装完成"
}
install_web() {
    # 放个小游戏到/srv/www
    web_www="${resource}/www.zip"
    wget --no-check-certificate -O www.zip $web_www
    unzip -o www.zip -d /srv/ && rm -f www.zip
}

config_caddy_base() {
    # json_name="caddy_base.json"
    # wget -N --no-check-certificate -O ${json_name} ${config_resource}/caddy/caddy_base.json
    # sed -i "s/PORT_HTTP1/${port_http1}/"  ${json_name}
    # sed -i "s/PORT_HTTP2/${port_http2}/"  ${json_name}
    # sed -i "s/TLS_PATH/${tls_path}/"  ${json_name}
    # sed -i "s/TLS_MODULE/${tls_module}/"  ${json_name}
    # sed -i "s/CERT_EMAIL/${Cert_Email}/"  ${json_name}

    cat > ${caddy_config} <<EOF
{
  "admin": {
    "disabled": true,
    "config": {
      "persist": false
    }
  },
  "logging": {
    "logs": {
      "default": {
        "writer": {
          "output": "file",
          "filename": "/var/log/caddy/default.log"
        },
        "encoder": {
          "format": "console"
        },
        "level": "WARN"
      }
    }
  },
  "storage": {
    "module": "file_system",
    "root": "${tls_path}" //存放 TLS 证书的基本路径
  },
  "apps": {
    "tls": {
      // "certificates": {
      //   "automate": [
      //     "${network_host}"
      //   ] //自动化管理 TLS 证书，域名添加到数组
      // },
      "automation": {
        "policies": [
          {
            "issuers": [
              {
                "module": "${tls_module}", //acme 表示从 Let's Encrypt 申请 TLS 证书，zerossl 表示从 ZeroSSL 申请 TLS 证书。必须 acme 与 zerossl 二选一（固定 TLS 证书的目录便于引用）
                "email": "${Cert_Email}" //创建账号后不需要变
              }
            ]
          }
        ]
      }
    },
    "http": {
      "servers": {
        "srvh1": {
          "listen": [
            ":80"
          ],
          "routes": [
            {
              "handle": [
                {
                  "handler": "static_response",
                  "headers": {
                    "Location": [
                      "https://{http.request.host}{http.request.uri}"
                    ] //HTTP 自动跳转 HTTPS，让网站看起来更真实
                  },
                  "status_code": 301
                }
              ]
            }
          ],
          "protocols": [
            "h1"
          ] //仅开启 HTTP/1.1 server 支持
        },
        "srvh2c": {
          "listen": [
            "127.0.0.1:${port_http1}"
          ], //H2C server 及 HTTP/1.1 server 本地监听端口
          "listener_wrappers": [
            {
              "wrapper": "proxy_protocol" //开启 PROXY protocol 接收
            }
          ],
          "protocols": [
            "h1",
            "h2c"
          ], //开启 HTTP/1.1 server 与 H2C server 支持
          "routes": [
            {
              "handle": [
                {
                  "handler": "headers",
                  "response": {
                    "set": {
                      "Strict-Transport-Security": [
                        "max-age=31536000; includeSubDomains; preload"
                      ] //启用 HSTS
                    }
                  }
                },
                {
                  "handler": "file_server",
                  "root": "/srv/www" //修改为自己存放的 WEB 文件路径
                }
              ]
            }
          ]
        },
        "srvh2": {
          "listen": [
            "127.0.0.1:${port_http2}"
          ], //HTTP/2 server 本地监听端口
          "listener_wrappers": [
            {
              "wrapper": "proxy_protocol" //开启 PROXY protocol 接收
            },
            {
              "wrapper": "tls" //HTTP/2 server 开启 PROXY protocol 接收必须配置
            }
          ],
          "protocols": [
            "h1",
            "h2"
          ], //开启 HTTPS server 与 HTTP/2 server 支持。（Caddy SNI 分流不支持 UDP 转发）
          "routes": [
            {
              "handle": [
                {
                  "handler": "headers",
                  "response": {
                    "set": {
                      "Strict-Transport-Security": [
                        "max-age=31536000; includeSubDomains; preload"
                      ] //启用 HSTS
                    }
                  }
                },
                {
                  "handler": "file_server",
                  "root": "/srv/www" //WEB 文件路径
                }
              ]
            }
          ],
          "trusted_proxies": {
            "source": "cloudflare", //cloudflare 为使用 cloudflare ips，由 caddy-cloudflare-ip 插件提供
            "interval": "12h",
            "timeout": "15s"
          } //配置可信代理服务器的 IP 范围，以实现套 CDN 后服务端记录的客户端 IP 为真实来源 IP。若使用其它非 Cloudflare CDN，需调整 trusted_proxies 配置
        }
      }
    },
    "layer4": {
      "servers": {
        "sni": {
          "listen": [
            ":443"
          ]
          //sni->routes
        }
      }
    }
  }
}
EOF
    sed -i "s/[^:]\/\/.*$//" ${caddy_config}
    sed -i "s/^\/\/.*$//" ${caddy_config}
    caddy_base=$(cat ${caddy_config})
}

config_caddy_tls() {
    caddy_tls=$(cat << EOF
{
  "apps": {
    "tls": {
      "certificates": {
        "automate": [
          "${network_host}"
        ]
      }
    }
  }
}
EOF
)
    caddy_json=$(cat ${caddy_config})
    automate_hosts=$(echo ${caddy_json} | jq .apps.tls.certificates.automate[])
    contains ${automate_hosts} ${network_host}

    if [ $? ]; then
        green "${network_host} is in the certificates automate list, do nothing"
    else
        echo -e ${caddy_json} ${caddy_tls} | jq -s add > ${caddy_config}
    fi
}

# caddy 前置分流
config_caddy_sni() {
    json_name="caddy_sni.json"
    cat > ${json_name} <<EOF
{
  "apps": {
    "layer4": {
      "servers": {
        "sni": {
          //sni->listen
          "routes": [
            {
              "match": [
                {
                  "tls": {
                    "sni": [
                      "${network_sni}"
                    ] //对应 VLESS+Vision+TLS 的域名
                  }
                }
              ],
              "handle": [
                {
                  "handler": "proxy",
                  "upstreams": [
                    {
                      "dial": [
                        "127.0.0.1:${server_port}"
                      ] //转给后端监听端口
                    }
                  ],
                  "proxy_protocol": "v2" //启用 PROXY protocol 发送，v1 或 v2 表示 PROXY protocol 版本，建议采用 v2 版
                }
              ]
            }
          ] //match-sni routes
        }
      }
    }
  }
}
EOF
    sed -i "s/[^:]\/\/.*$//" ${json_name}
    sed -i "s/^\/\/.*$//" ${json_name}
    caddy_sni=$(cat ${json_name})
    rm -f ${json_name}

    caddy_json=$(cat ${caddy_config})
    exist_sni=$(echo ${caddy_json} | jq .apps.layer4.servers.servers.sni.routes.match.tls.sni[])
    contains ${exist_sni} ${network_sni}

    if [ $? ]; then
        green "${network_sni} is in the certificates automate list, do nothing"
    else
        echo -e ${caddy_json} ${caddy_sni} | jq -s add > ${caddy_config}
    fi
}

config_caddy_Vmess() {
    json_name="caddy_Vmess.json"
    cat > ${json_name} <<EOF
{
  "apps": {
    "http": {
      "servers": {
        "srvh2": {
          //srvh2->listen
          "routes": [
            {
              "match": [
                {
                  "path": [
                    "${network_path}"
                  ], //与 VMess+WebSocket 应用中 path 对应
                  "header": {
                    "Connection": [
                      "*Upgrade*"
                    ],
                    "Upgrade": [
                      "websocket"
                    ]
                  }
                }
              ],
              "handle": [
                {
                  "handler": "reverse_proxy",
                  "upstreams": [
                    {
                      "dial": "127.0.0.1:${server_port}" //转发给本机 VMess+WebSocket 监听端口
                    }
                  ]
                }
              ]
            }
          ]//,tls_connection_policies
        }
      }
    }
  }
}
EOF
    sed -i "s/[^:]\/\/.*$//" ${json_name}
    sed -i "s/^\/\/.*$//" ${json_name}
    caddy_Vmess=$(cat ${json_name})
    rm -f ${json_name}

    caddy_json=$(cat ${caddy_config})
    exist_path=$(echo ${caddy_json} | jq .apps.http.servers.srvh2.routes.match.path[])
    contains ${exist_path} ${network_path}

    if [ $? ]; then
        green "${network_path} is in the certificates automate list, do nothing"
    else
        echo -e ${caddy_json} ${caddy_Vmess} | jq -s add > ${caddy_config}
    fi
}

config_caddy_Vless() {
    json_name="caddy_Vless.json"
    cat > ${json_name} <<EOF
{
  "apps": {
    "http": {
      "servers": {
        "srvh2": {
          //srvh2->listen
          "routes": [
            {
              "match": [
                {
                  "path": [
                    "${network_path}"
                  ] //与 VLESS+H2C 应用中 path 对应
                }
              ],
              "handle": [
                {
                  "handler": "reverse_proxy",
                  "transport": {
                    "protocol": "http",
                    "versions": [
                      "h2c",
                      "2"
                    ]
                  },
                  "upstreams": [
                    {
                      "dial": "127.0.0.1:${server_port}" //转发给本机 VLESS+H2C 监听端口
                    }
                  ]
                }
              ]
            }
          ]//,tls_connection_policies
        }
      }
    }
  }
}
EOF
    sed -i "s/[^:]\/\/.*$//" ${json_name}
    sed -i "s/^\/\/.*$//" ${json_name}
    caddy_Vless=$(cat ${json_name})
    rm -f ${json_name}

}

config_caddy_Trojan() {
    cat >>${caddy_config} <<EOF

EOF

}

config_caddy_Shadowsocks() {
    cat >>${caddy_config} <<EOF

EOF

}

# 输出配置信息，供其他程序离线使用
config_info() {
    cat >~/.config_info.json <<EOF
{
    "api": {
        "Api_Host": "${Api_Host}",
        "Api_Key": "${Api_Key}"
    },
    "node": {
        "Node_ID": "${Node_ID}",
        "Node_Type": "${Node_Type}"
    },
    "dns": {
        "CF_TOKEN_DNS": "${CF_TOKEN_DNS}"
    },
    "db": {
        "DB_Host": "${DB_Host}",
        "DB_Name": "${DB_Name}",
        "DB_User": "${DB_User}",
        "DB_PWD": "${DB_PWD}"
    }
}
EOF
}

auto_Port(){
    autoPort_url="https://github.com/cdnf/shell/raw/master/proxy/autoPort.sh"
    wget -N --no-check-certificate -O autoPort.sh ${autoPort_url}
    bash autoPort.sh
}

# https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
dns_update() {
    CFZONE_NAME=${network_host#*\.}
    CFRECORD_NAME=${network_host}
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

srv_frame() {
    # 规则组合：https://github.com/XTLS/Xray-examples
    # 规则组合：https://github.com/lxhao61/integrated-examples
    # echo
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
    echo -e "2. XrayR --> Caddy"
    echo -e "本脚本默认使用Caddy，其他nginx，httpd等将会被禁用"
    echo -e "========================================================="
    read -p "请选择方案组合（默认 1）：" front_srv
    [[ -z "${front_srv}" ]] && front_srv="1"

    case ${front_srv} in
      1)
        Cert_Mode="none"
        ;;
      2)
        Cert_Mode="file"
        ;;
      *)
        echo "请输入正确数字[1-2]:"
        ;;
    esac
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
    bold "准备安装 XrayR"
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
        red "下载 XrayR ${XrayR_version} 失败，请确保此版本存在且服务器能够下载 Github 文件"
        exit 1
    fi

    unzip XrayR-linux-64.zip && rm -f XrayR-linux-64.zip
    chmod +x XrayR
    XrayR_service="https://github.com/XrayR-project/XrayR-release/raw/master/XrayR.service"
    wget -N --no-check-certificate -O /etc/systemd/system/XrayR.service ${XrayR_service}
    systemctl daemon-reload && systemctl stop XrayR
    systemctl enable XrayR
    green "XrayR ${XrayR_version} 安装完成，已设置开机自启"
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
        config_set && srv_frame
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
            green "XrayR 重启成功"
        else
            echo
            red "XrayR 可能启动失败，请稍后使用 XrayR log 查看日志信息，若无法启动，"
            red "则可能更改了配置格式，请前往 wiki 查看：https://crackair.gitbook.io/xrayr-project/"
        fi
    fi
    # 安装管理工具
    XrayR_tool

    if [[ -f /usr/sbin/firewalld ]]; then
        echo "正在关闭防火墙！"
        systemctl disable firewalld
        systemctl stop firewalld
    fi
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

    echo -e "[1] Vmess \t [2] Trojan \t [3] Shadowsocks"
    read -p "节点类型（默认Vmess）：" node_num
    [ -z "${node_num}" ] && node_num="1"
    if [[ "$node_num" == "1" ]]; then
        Node_Type="Vmess"
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
    if [[ -z ${CF_TOKEN_DNS} ]]; then
        read -p "CloudFlare域名管理Token：" CF_TOKEN_DNS
    fi

    # 从面板获取节点关键信息
    config_GetNodeInfo
    # caddy监控443和80，通过path分流到后端，所以后端服务不能设置caddy 已用端口
    contains "80 443 ${port_http1} ${port_http2}" "${server_port}" 
    if [[ $? == 0 ]]; then
        red "端口与 80 443 ${port_http1} ${port_http2} 有冲突，请到面板修改为其他端口"
        pause_press
        config_set
    fi

    echo
    green "\t面板类型：V2bord"
    green "\t节点类型：${Node_Type}"
    green "\t节点ID：${Node_ID}"
    green "\t对外连接地址：${network_host}"
    green "\t对外连接端口：${network_port}"
    green "\t后端监听端口：${server_port}"
    green "\t传输协议：${network_protocol}"
    green "\t加密方式：${network_security}"
    if [[ "${Node_Type}" == "Trojan" ]]; then
        green "\t伪装域名「serverName」：${network_sni}"
    fi
    if [[ "${Node_Type}" == "Vmess" || "${Node_Type}" == "V2ray" ]]; then
        green "\t伪装域名「serverName」：${network_sni}"
        green "\t分流路径「path」：${network_path}"
    fi
    if [[ "${Node_Type}" == "Shadowsocks" ]]; then
        green "\t混淆域名「serverName」：${network_sni}"
        green "\t混淆路径「path」：${network_path}"
    fi
    echo
    read -p "以上信息确认正确就回车继续，否则请输 N 重来：" Check_All
    if [[ ${Check_All} == "N" ]]; then
        config_set
    fi
    config_TLS

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

    if [[ "${Node_Type}" == "Vmess" || "${Node_Type}" == "V2ray" ]]; then
        config_caddy_Vmess
    fi
    if [[ "${Node_Type}" == "Vless" ]]; then
        config_caddy_Vless
    fi
    if [[ "${Node_Type}" == "Trojan" ]]; then
        config_caddy_Trojan
    fi
    if [[ "${Node_Type}" == "Shadowsocks" ]]; then
        config_caddy_Shadowsocks
    fi

}

# 菜单
menu() {
    echo
    echo -e "======================================"
    echo -e "	Author: 金三将军"
    echo -e "	Version: 0.1.4"
    echo -e "======================================"
    echo
    echo -e "\t1.安装XrayR"
    echo -e "\t2.新增nodes"
    echo -e "\t3.开启定期更换端口"
    echo -e "\t4.开启系统Swap"
    echo -e "\t9.卸载XrayR"
    echo -e "\t0.退出\n"
    echo
    read -ep "请输入数字选项: " menu_Num
}
while [[ 1 ]]; do
    menu
    case "${menu_Num}" in
      0)
          break
          ;;
      1)
          install_XrayR
          config_info && install_Caddy
          config_caddy_base && config_caddy_tls
          green "安装完成，正在尝试重启服务..."
          systemctl restart caddy
          XrayR restart
          ;;
      2)
          config_set
          config_nodes && config_Cert
          XrayR restart && XrayR log
          ;;
      3)
          auto_Port
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
