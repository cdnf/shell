#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 6+/Ubuntu 14.04+
#	Description: Install the base software
#	Version: 0.0.1
#	Author: 金将军
#	homepage: https://sobaigu.com
#=================================================

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} 当前账号没有ROOT权限，无法继续操作，请使用${Green_background_prefix} sudo su ${Font_color_suffix}来获取临时ROOT权限（执行后会提示输入当前账号的密码）。" && exit 1
}

sys_bit=$(uname -m)
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

#更新系统
$installcmd -y --exclude=kernel* update
#安装常用基础软件
$installcmd -y install vim lrzsz screen git unzip ntp crontab net-tools telnet gcc gcc-c++ make automake autoconf libtool
$installcmd -y install && chown -R vnstat:vnstat /var/lib/vnstat && service_Cmd restart vnstat
#设置时区为东八区
echo yes | cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
#同步时间
ntpdate cn.pool.ntp.org
#添加系统定时任务自动同步时间并重启定时任务服务
sed -i '/^.*ntpdate*/d' /etc/crontab
sed -i '$a\0 1 * * 1 root ntpdate cn.pool.ntp.org >> /dev/null 2>&1' /etc/crontab
service_Cmd restart crond
#/etc/init.d/crond restart
#把时间写入到BIOS
hwclock -w
