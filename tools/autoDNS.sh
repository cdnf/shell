#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

export LC_ALL=C
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8

cur_dir=$(pwd)
resource="https://github.com/cdnf/shell/raw/master/resource"
caddy_config="/etc/caddy/Caddyfile"
tls_module="acme"   #TLS证书机构: acme (Let's Encrypt) | zerossl (ZeroSSL)

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
local_tool="wget curl git unzip gzip tar screen lrzsz socat sudo jq cron dnsutils net-tools file ntpdate systemd-timesyncd"
if [[ -f /usr/bin/apt && -f /bin/systemctl ]]; then
  os="debian"
  cron_srv="cron"
  INS="apt -y install"
  apt -y update
  $INS ${local_tool}
  # wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq
  # curl -L https://github.com/a8m/envsubst/releases/latest/download/envsubst-`uname -s`-`uname -m` -o /usr/bin/envsubst && chmod +x /usr/bin/envsubst
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

if [[ -f /usr/sbin/firewalld ]]; then
  echo "正在关闭防火墙！"
  systemctl disable firewalld
  systemctl stop firewalld
fi

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

# contains aList anItem
contains() {
  aList=($1)
  anItem=$2

  matched="false"
  for item in {${aList[@]}}; do
    if [[ ${item} == ${anItem} ]]; then
      matched="true"
      green "${anItem} 与数组元素匹配成功"
    fi
  done
}

config_GetNodeInfo() {
  NodeInfo_API="${Api_Host}/api/v1/server/UniProxy/config?token=${Api_Key}&node_id=${Node_ID}"
  NodeInfo_json=$(curl -s "${NodeInfo_API}" | jq .)

  # 公共参数
  # 对外连接域名，需接口增加 host 字段输出
  network_host=$(echo ${NodeInfo_json} | jq -r '.host')
  # 对外连接端口，需接口增加 port 字段输出
  network_port=$(echo ${NodeInfo_json} | jq -r '.port')
  # 后端监听端口
  server_port=$(echo ${NodeInfo_json} | jq -r '.server_port')
  # 节点类型
  server_protocol=$(echo ${NodeInfo_json} | jq -r '.protocol')

  if [[ "${server_protocol}" == "Trojan" ]]; then
    # 加密方式：tls|xtls|none，Trojan强制tls
    network_security="tls"
    # 传输协议：tcp|grpc|ws才对接caddy,v2board默认只有tcp
    network_protocol="tcp"
    # 伪装serverName，回落对接用
    network_sni=$(echo ${NodeInfo_json} | jq -r '.server_name')
  elif [[ "${server_protocol}" == "Vmess" || "${server_protocol}" == "V2ray" ]]; then
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
  elif [[ "${server_protocol}" == "Shadowsocks" ]]; then
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
  if [[ "${network_sni}" == "null" || -z ${network_sni} ]]; then
    network_sni=${network_host}
  fi

  echo
  green "从 ${Api_Host} 获取 ${Node_ID} 号 ${server_protocol} 节点信息完成"
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
        "server_protocol": "${server_protocol}"
    },
    "dns": {
        "CF_TOKEN_DNS": "${CF_TOKEN_DNS}"
    }
}
EOF
}

# https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
dns_update() {
  CFZONE_NAME=${network_host#*\.}
  CFRECORD_NAME=${network_host}

  if [[ -z ${network_host} ]]; then
    read -p "请输入需要解析的域名：" network_host
    echo -e "输入的域名为：${network_host}"
    echo "确认无误按任意键继续，否则按 CTRL+C 退出重来"
    pause
  fi

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


# 指定节点解析时用到
config_set() {
  if [[ -z ${Api_Key} ]]; then
    read -p "前端面板认证域名（包括http[s]://）：" Api_Host
    read -p "前端面板的apikey：" Api_Key
  fi

  read -p "面板里的节点ID：" Node_ID
  [ -z "${Node_ID}" ] && Node_ID=1

  # 通过cloudflare解析域名，不支持cf，ml，tk，gq等烂大街的免费域名
  # CF_Token=$(cat ~/.acme.sh/account.conf | grep SAVED_CF_Token= | awk -F "'" '{print $2}')
  if [[ -z ${CF_TOKEN_DNS} ]]; then
    read -p "CloudFlare域名管理Token：" CF_TOKEN_DNS
  fi

  # 从面板获取节点关键信息
  config_GetNodeInfo

  echo
  green "\t节点ID：${Node_ID}"
  green "\t节点类型：${server_protocol}"
  green "\t对外连接地址：${network_host}"
  green "\t对外连接端口：${network_port}"
  green "\t后端监听端口：${server_port}"
  green "\t传输协议：${network_protocol}"
  green "\t加密方式：${network_security}"
  echo
  read -p "以上信息确认正确就回车继续，否则请输 N 重来：" Check_All
  if [[ ${Check_All} == "N" ]]; then
    config_set
  fi
}

# 菜单
menu() {
  echo
  echo -e "======================================"
  echo -e "	Author: 金三将军"
  echo -e "	Version: 0.0.1"
  echo -e "	偷懒的一些小功能"
  echo -e "======================================"
  echo
  echo -e "[1].指定节点解析"
  echo -e "[2].输入域名解析"
  echo -e "[Q].退出\n"
  echo
  read -ep "请输入数字选项: " menu_Num
}
while [[ 1 ]]; do
  menu
  case "${menu_Num}" in
  Q|q)
    break
    ;;
  1)
    config_set && config_info
    dns_update
    ;;
  2)
    dns_update
    ;;
  *)
    echo "请输入正确数字:"
    ;;
  esac
done
clear