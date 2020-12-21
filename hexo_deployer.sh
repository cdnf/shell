#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 6+/Ubuntu 14.04+
#	Author: 金将军
#	homepage: https://sobaigu.com
#=================================================

# Make sure only root can run our script
[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

v2config="/etc/v2ray/config.json"
tls_path="/root/.cert/"

#Check system
if [[ -f /usr/bin/apt ]] || [[ -f /usr/bin/yum && -f /bin/systemctl ]]; then
	if [[ -f /usr/bin/yum ]]; then
		installcmd="yum"
		$installcmd -y install epel-release
	fi
	if [[ -f /usr/bin/apt ]]; then
		installcmd="apt"
	fi
	if [[ -f /bin/systemctl ]]; then
		systemd=true
	fi

else
	echo -e " 哈哈……这个 ${red}辣鸡脚本${none} 只支持CentOS7+及Ubuntu14+ ${yellow}(-_-) ${none}" && exit 1
fi
service_Cmd(){
	if [[ $systemd ]]; then
		systemctl $1 $2
	else
		service $2 $1
	fi
}

config_ID(){
	read -p "$(echo -e "$yellow输入节点ID$none")：" node_ID
}
config_domain(){
	read -p "$(echo -e "$yellow输入节点域名$none")：" myDomain
}
config_node(){
	read -p "$(echo -e "$yellow输入webAPI域名（包括协议）$none")：" webAPI
	read -p "$(echo -e "$yellow输入token（18个以上字符）$none")：" token
	read -p "$(echo -e "$yellow用户限速$none（字节/秒，默认：${cyan}0=不限速$none）")：" speedLimit_user
		[ -z "$speedLimit_user" ] && speedLimit_user="0"
	read -p "$(echo -e "$yellow最大在线IP数$none(默认：${cyan}2$none)")：" maxOnlineIPCount
		[ -z "$maxOnlineIPCount" ] && maxOnlineIPCount="2"
}

v2ray_restart(){
	service_Cmd restart v2ray
	sleep 5
	service_Cmd status v2ray
}

v2ray_install(){
	v2ray_uninstall
	v2ray_update
	config_ID
	config_node
	# 生成v2board配置
	echo -e '{
	"poseidon": {
		"panel": "v2board",	// 这一行必须存在，且不能更改
		"nodeId": 1,	// 你的节点 ID 和 v2board 里的一致
		"checkRate": 60,	// 每隔多长时间同步一次配置文件、用户、上报服务器信息
		"webapi": "http://webapi.sobaigu.com",	// v2board 的域名信息，带协议
		"token": "password4sobaigu.com",	// v2board 和 v2ray-poseidon 的通信密钥
		"speedLimit": 0,	// 节点限速 单位 字节/s 0 表示不限速
		"user": {
			"maxOnlineIPCount": 2,	// 用户同时在线 IP 数限制 0 表示不限制
			"speedLimit": 0	// 用户限速 单位 字节/s 0 表示不限速
		}
	}
}' > $v2config
	sed -i "s|\"nodeId\":.*,|\"nodeId\": $node_ID,|" $v2config
	sed -i "s|\"webapi\":.*,|\"webapi\": \"$webAPI\",|" $v2config
	sed -i "s|\"token\":.*,|\"token\": \"$token\",|" $v2config
	cat $v2config
	v2ray_restart
}

v2ray_edit(){
	config_ID
	config_node
	sed -i "s|\"nodeId\":.*,|\"nodeId\": $node_ID,|" $v2config
	sed -i "s|\"webapi\":.*,|\"webapi\": \"$webAPI\",|" $v2config
	sed -i "s|\"token\":.*,|\"token\": \"$token\",|" $v2config
	sed -i "s|\"maxOnlineIPCount\":.*,|\"maxOnlineIPCount\": $maxOnlineIPCount,|" $v2config
	sed -i "s|\"speedLimit\":.*\/\/ 用户|\"speedLimit\": $speedLimit_user	\/\/ 用户|" $v2config
	cat $v2config
	v2ray_restart
}

v2ray_update(){
	# 安装v2ray最新版
	curl -L -s https://raw.githubusercontent.com/ColetteContreras/v2ray-poseidon/master/install-release.sh | bash
}
v2ray_uninstall(){
	service_Cmd stop v2ray
	service_Cmd disable v2ray
	update-rc.d -f v2ray remove
	rm -rf /usr/bin/v2ray /etc/init.d/v2ray /lib/systemd/system/v2ray.service

	set -

	echo "Logs and configurations are preserved, you can remove these manually"
	echo "logs directory: /var/log/v2ray"
	echo "configuration directory: /etc/v2ray"
}

tls_acme_install(){
	# 安装依赖
	$installcmd install -y socat
	# 安装acme.sh
	curl  https://get.acme.sh | sh
	source ~/.bashrc
	config_domain
	# 使用 acme.sh 生成证书
	~/.acme.sh/acme.sh --issue -d $myDomain --standalone -k ec-256
	tls_acme_deploy
}
tls_acme_update(){
	config_domain
	# 证书有效期只有 3 个月，因此需要 90 天至少要更新一次证书，acme.sh 脚本会每 60 天自动更新证书。也可以手动更新。
	~/.acme.sh/acme.sh --renew -d $myDomain --force --ecc
	tls_acme_deploy
}
tls_acme_deploy(){
	mkdir $tls_path
	~/.acme.sh/acme.sh --installcert -d $myDomain --fullchainpath $tls_path$tls_crt --keypath $tls_path$tls_key --ecc
	v2ray_restart
}

# 菜单
echo -e "1.安装v2ray"
echo -e "2.升级v2ray"
echo -e "3.修改配置"
echo -e "4.安装acme申请证书"
echo -e "5.更新TLS证书"
read -p "请输入数字进行安装[1-5]:" menu_Num
case "$menu_Num" in
	1)
	v2ray_install
	;;
	2)
	v2ray_update
	;;
	3)
	v2ray_edit
	;;
	4)
	tls_acme_install
	;;
	5)
	tls_acme_update
	;;
	*)
	echo "请输入正确数字[1-5]:"
	;;
esac
