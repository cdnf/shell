yum groupinstall -y "KDE Plasma Workspaces" "Graphical Administration Tools" && systemctl set-default graphical.target
yum -y install tigervnc-server && cp -f /lib/systemd/system/vncserver@.service /etc/systemd/system/vncserver.conf
cd /etc/systemd/system
sed -i '/^User=/c\User=root' vncserver.conf
sed -i '/^PIDFile=/c\PIDFile=/root/.vnc/%H%i.pid' vncserver.conf
sed -i '/^WantedBy=/c\WantedBy=graphical.target' vncserver.conf
mv -f vncserver.conf vncserver@:1.service
systemctl daemon-reload
firewall-cmd --permanent --add-service vnc-server && systemctl restart firewalld.service && systemctl enable vncserver@:1.service
vncpasswd && reboot


# VNC远程服务端需开放5901端口
# 客户端安装VNC Viewer或TigerVNC
# 连接地址填写ip:5901
# 然后输入所设置的VNC密码

# 设置永久开启VNC服务
# systemctl enable vncserver@:1.service
# 启动VNC服务
# systemctl start vncserver@:1.service
# 如遇报错：
# Job for vncserver@:1.service failed because the control process exited with error code. See "systemctl status vncserver@:1.service" and "journalctl -xe" for details.
# 编辑/etc/systemd/system/vncserver@:1.service配置文件：
# 将Type=forking改为Type=simple
# 重新启动VNC服务
# systemctl restart vncserver@:1.service
# 查看VNC服务状态
# systemctl status vncserver@:1.service
# 如有Activie:failed则表示启动失败
# 编辑/etc/systemd/system/vncserver@:1.service配置文件：
# 将里面所有的<USER>替换为当前用户名(大致有两处)，如root；另，如果是root用户，应将PIDFile的/home/root改为/root
# 重新启动VNC服务
# systemctl restart vncserver@:1.service