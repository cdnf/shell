#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cmd=$(apt -v)
if [[ -z $cmd ]]; then
    echo
    echo "只支持Debian/Ubuntu，垃圾脚本就是这样……"
    exit 1
fi
apt install -y curl wget cron jq net-tools

if [[ -z $(mysql -V) ]]; then
    apt install -y default-mysql-client
fi

#===========================================#
# Version: 0.1.1
# Author: 金三将军
# Homepage：
# ------------------------------------------#
# 1. 节点机：列出当前节点设置的访问端口和域名
# 2. 节点机：随机一个端口，直到不与已启用端口冲突
# 3. 节点机：同步新访问端口和host到caddy配置，并reload
# 4. 节点机/服务器：将随机端口设置为节点访问新端口
# 5. 探测机：定期检测远程端口，不通则触发更换随机端口
# 6. 基础信息：Api_Host, Api_Key, Node_ID, Node_Type
# 7. 获取数据：network_host, network_port
# 8. 数据操作：db_user, db_pwd
# 9. 域名解析：CF_DNS_API_TOKEN
#===========================================#

# 获取基础信息
load_Config() {
    config_info=$(cat ~/.config_info.json | jq .)
    if [[ "$?" == 0 ]]; then
        echo -e "${green}Get local config sucessed...${plain}"
    else
        echo -e "${red}Get local config failed, please check ~/.config_info.json${plain}"
        exit 1
    fi

    Api_Host=$(echo ${config_info} | jq -r '.api.Api_Host')
    Api_Key=$(echo ${config_info} | jq -r '.api.Api_Key')
    Node_ID=$(echo ${config_info} | jq -r '.node.Node_ID')
    Node_Type=$(echo ${config_info} | jq -r '.node.Node_Type')
    CF_DNS_API_TOKEN=$(echo ${config_info} | jq -r '.dns.CF_DNS_API_TOKEN')
    DB_Host=$(echo ${config_info} | jq -r '.db.DB_Host')
    DB_Name=$(echo ${config_info} | jq -r '.db.DB_Name')
    DB_User=$(echo ${config_info} | jq -r '.db.DB_User')
    DB_PWD=$(echo ${config_info} | jq -r '.db.DB_PWD')
}

# 查询对应节点当前连接域名和端口
query_Host_Port() {
    api_url="${Api_Host}/api/v1/server/UniProxy/config?token=${Api_Key}&node_type=${Node_Type,,}&node_id=${Node_ID}"
    if [[ "$?" == 0 ]]; then
        echo -e "${green}Get data from api sucessed...${plain}"
    else
        echo -e "${red}Get data from api failed, please check...${plain}"
        exit 2
    fi
    api_data=$(curl -s "${api_url}" | jq .)

    # 对外连接域名，需接口增加 host 字段输出
    network_host=$(echo ${api_data} | jq -r '.host')
    # 对外连接端口，需接口增加 port 字段输出
    network_port=$(echo ${api_data} | jq -r '.port')
    # 后端监听端口
    inbound_port=$(echo ${api_data} | jq -r '.server_port')

    echo
    echo -e "\t节点ID：${green}${Node_ID}${plain}"
    echo -e "\t节点类型：${green}${Node_Type}${plain}"
    echo -e "\t对外连接地址：${green}${network_host}${plain}"
    echo -e "\t对外连接端口：${green}${network_port}${plain}"
    echo -e "\t后端监听端口：${green}${inbound_port}${plain}"
}

# 生成随机数
random_Num() {
    # 指定随机数范围
    echo "starting generate random number"
    arr=($(seq 1000 10000))
    num=${#arr[*]}
    port_new=${arr[$(($RANDOM % num))]}
    port_exist=$(netstat -na | awk '{print $4}' | grep ":" | awk -F ':' '{print $NF}' | awk '!a[$1]++{print}' | grep ${port_new})
}

# 随机新端口，不能与现有端口冲突
new_Port() {
    echo -e "random port is ${port_new}"
    while [[ -n ${port_exist} ]];
    do  
        random_Num
    done
    echo -e "Now, the new port is ${green}${port_new}${plain}"
}

# 同步到前端caddy
set_Caddy() {
    Caddyfile="/etc/caddy/Caddyfile"
    sed -i "s|${network_host}:${network_port}|${network_host}:${port_new}|" ${Caddyfile}
    sed -i "s|@${Node_Type}_${Node_ID} localhost:.*|@${Node_Type}_${Node_ID} localhost:${inbound_port}|" ${Caddyfile}
    systemctl reload caddy || systemctl restart caddy

    if [[ "$?" == 0 ]]; then
        echo -e "caddy has been reloaded new port: ${green}${port_new}${plain}"
    else
        echo -e "${red}caddy  reloaded failed, please check...${plain}"
        exit 1
    fi
}

# 添加到系统定时任务
set_Crontab() {
    file_sh=$(realpath $0)
    chmod +x ${file_sh}
    ln -sf ${file_sh} /usr/bin/autoPort

    sed -i '/^.*autoPort.*/d' /etc/crontab
    sed -i '$a\30 3 * * * root autoPort >> /dev/null 2>&1' /etc/crontab

    if [[ "$?" == 0 ]]; then
        echo -e "${green}${file_sh}${plain} has been add in cron task"
    else
        echo -e "${red}DB operate failed, please check...${plain}"
        exit 1
    fi
    systemctl restart cron
    echo
    echo -e "the file of shell is ${file_sh}"
    echo
    echo "and you can use command: autoPort"
}

# 操作数据库，将新端口同步到面板配置
sync_DB() {
    if [[ -z ${DB_Host} ]]; then
        read -p "请配置数据库地址：" DB_Host
    elif [[ -z ${DB_Name} ]]; then
        read -p "请配置数据库名称：" DB_Name
    elif [[ -z ${DB_User} ]]; then
        read -p "请配置数据库用户：" DB_User
    elif [[ -z ${DB_PWD} ]]; then
        read -p "请配置数据库密码：" DB_PWD
    fi

    db_table="v2_server_${Node_Type,,}"
    SQL="UPDATE ${db_table} SET port = ${port_new} WHERE ${db_table}.id = ${Node_ID}"
    mysql -h"${DB_Host}" -u"${DB_User}" -p"${DB_PWD}" -D"${DB_Name}" -B -e "$SQL"
    if [[ "$?" == 0 ]]; then
        echo -e "new port: ${green}${port_new}${plain} has updated to the panel"
    else
        echo -e "${red}DB operate failed, please check...${plain}"
        exit 2
    fi
}

load_Config && query_Host_Port
random_Num && new_Port
sync_DB && set_Caddy && set_Crontab

# 检测端口状态，需跨网异地使用才有效，所以基础信息需要额外处理
tcping_Install() {
    apt install python3-pip
    pip install tcping
    tcp_help=$(tcping --help)
    if [[ $tcp_help ]]; then
        echo -e "很好，tcping ${yellow}安装成功 ${none}"
    else
        echo -e "${red}tcping 命令不成功，安装失败了，检查下 ${none}"
    fi
}
tcping_Test() {
    time_test=10
    time_sleep=$[${time_test}*2]
    success_percent=20
    test=$(tcping -c ${time_test} ${network_host} -p ${network_port} | grep "success rate" | awk '{print $7}')
    test=$(tcping -c 1 wubase.com -p 139 | grep "success rate" | awk '{print $7}')
    sleep ${time_sleep}
    rate=$(echo ${test%%.*})
    if [[ ${rate} < ${success_percent} ]]; then
        echo "just to be continue..."
        # random_Num
        # new_Port
        # sync_DB
        # set_Caddy
    fi
}
