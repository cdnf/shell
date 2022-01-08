#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

nat_conf="/etc/nat.conf"
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
  $cmd -y install ${dependency}
else
  echo -e "${red}未检测到系统版本，本程序只支持CentOS，Ubuntu和Debian！，如果检测有误，请联系作者${plain}\n" && exit 1
fi
sys_bit=$(uname -m)
if [[ ${sys_bit} != "x86_64" ]]; then
  echo "本软件不支持 32 位系统(x86)，请使用 64 位系统(x86_64)，如果检测有误，请联系作者"
  exit 2
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

install_nft() {
  systemctl disable firewalld
  setenforce 0
  sed -i 's|SELINUX=enforcing|SELINUX=disabled|' /etc/selinux/config
  sed -n '|^net.ipv4.ip_forward=1|'p /etc/sysctl.conf | grep -q "net.ipv4.ip_forward=1"
  echo 1 >/proc/sys/net/ipv4/ip_forward
  if [ $? -ne 0 ]; then
    echo -e "net.ipv4.ip_forward=1" >>/etc/sysctl.conf && sysctl -p
  fi
  $cmd -y install nftables && echo -e "nftables安装完成，并禁用了防火墙"
}

install_nat() {
  # https://github.com/arloor/nftables-nat-rust
  # dnat="http://cdn.arloor.com/tool/dnat"
  dnat="https://github.com/cdnf/shell/raw/master/resource/dnat"
  wget -O /usr/local/bin/nat ${dnat}
  chmod +x /usr/local/bin/nat
  # 创建systemd服务
  cat >/lib/systemd/system/nat.service <<EOF
[Unit]
Description=dnat-service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/nat ${nat_conf}
LimitNOFILE=100000
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload && systemctl enable nat
  echo -e "nat服务安装完成"
  echo
  read -p "是否进行配置「y/n」默认 y：" new_conf
  [ -z "${new_conf}" ] && new_conf="y"

  if [[ ${new_conf} == "y" ]]; then
    config_set
    config_nat
    systemctl start nat && systemctl status nat
    config_show
  else
    echo -e "请添加配置后再使用"
  fi
}

config_del() {
  config_show
  echo
  read -p "输入需要删除的行序号：" row_num
  if echo ${row_num} | grep -q '[0-9]'; then
    sed -i "${row_num}d" ${nat_conf}
    config_show
    echo
    echo -e "配置已删除，大约 1 分钟后生效"
  else
    echo "请输入正确数字"
  fi
}

config_nat() {
  # 生成配置文件，配置文件可按需求修改
  cat >>${nat_conf} <<EOF
${flag_port},${s_ports},${d_ports},${d_addr}
EOF
}

config_review() {
  flag_port=$(echo ${trans_conf} | awk -F "," '{print $1}')
  s_port=$(echo ${trans_conf} | awk -F "," '{print $2}')
  d_addr=$(echo ${trans_conf} | awk -F "," '{print $4}')
  d_port=$(echo ${trans_conf} | awk -F "," '{print $3}')

  if [ "${flag_port}" == "SINGLE" ]; then
    str="单个端口"
    s_ports=${s_port}
    d_ports=${d_port}
  elif [ "${flag_port}" == "RANGE" ]; then
    str="区间端口"
    s_ports="${s_port} ~ ${d_port}"
    d_ports="${s_port} ~ ${d_port}"
  else
    echo -e "未匹配相关配置"
    str=""
    s_ports=""
    d_ports=""
  fi
}

config_show() {
  count_line=$(awk 'END{print NR}' ${nat_conf})
  if [[ ${count_line} ]]; then
    echo
    echo -e "                      nftnat 现存配置                        "
    echo -e "------------------------------------------------------------------------"
    echo -e "序号\t|转发方式\t|本地端口\t|目标地址\t|目标端口"
    echo -e "------------------------------------------------------------------------"

    for ((i = 1; i <= ${count_line}; i++)); do
      trans_conf=$(sed -n "${i}p" ${nat_conf})
      config_review

      echo -e " ${i}\t|${str}\t|${s_ports}\t|${d_addr}\t|${d_ports}"
      echo -e "------------------------------------------------------------------------"
    done
  else
    echo -e "找不到配置文件 ${nat_conf}" && exit 2
  fi
}

config_set() {
  echo
  echo -e "[1] 单个端口 \t [2] 区间端口"
  read -p "转发方式「默认单个端口」：" ports_range
  [ -z "${ports_range}" ] && ports_range="1"
  if [[ ${ports_range} == 2 ]]; then
    flag_port="RANGE"
    read -p "起始端口：" s_ports
    read -p "结束端口：" d_ports
  else
    flag_port="SINGLE"
    read -p "本地端口：" s_ports
    read -p "目标端口：" d_ports
  fi
  read -p "目标地址：" d_addr
}

# 自定义转发规则
# /etc/nat.conf如下：
# SINGLE,49999,59999,baidu.com //SINGLE：单端口转发：本机49999端口转发到baidu.com:59999
# RANGE,50000,50010,baidu.com //RANGE：范围端口转发：本机50000-50010转发到baidu.com:50000-50010
# 每行代表一个规则；行内以英文逗号分隔为4段内容
# 请确保配置文件符合格式要求，否则程序可能会出现不可预期的错误
# 修改配置后，无需重新启动vps或服务，程序将会自动在最多一分钟内更新nat转发规则

menu() {
  echo
  echo -e "======================================"
  echo -e "	Author: 金将军"
  echo -e "	Version: 1.0.0"
  echo -e "======================================"
  echo
  echo -e "\t1.安装 nftnat"
  echo -e "\t2.新增转发配置"
  echo -e "\t3.删除现存转发"
  echo -e "\t4.查看现存配置"
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
    install_nft
    install_nat
    ;;
  2)
    config_set
    config_nat && config_show
    ;;
  3)
    config_del
    ;;
  4)
    config_show
    ;;
  *)
    echo "请输入正确数字:"
    ;;
  esac
done
clear
