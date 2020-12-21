yum groupinstall "X Window System" "KDE Desktop" Desktop -y
yum install vnc-server -y
vncpasswd
vncserver
chmod +x ~/.vnc/xstartup
service vncserver restart
chkconfig vncserver on