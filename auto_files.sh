#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	Author: 金将军
#	homepage: https://sobaigu.com
#   Feature: local-->baiduYun_dirA-->VPS_zip_replace-->upload{baiduYun_dirB,lanzouCloud}
#=================================================
python3_ver='3.8.5'
lanzouCloud_CMD_path='/usr/local/lanzouCloud_CMD/'
dir_syncdown='/root/.autofiles/syncdown/'
dir_syncup='/root/.autofiles/syncup/'

# Make sure only root can run our script
[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1
#Check system
if [[ -f /usr/bin/apt ]] || [[ -f /usr/bin/yum && -f /bin/systemctl ]]; then
    if [[ -f /usr/bin/yum ]]; then
        pm_CMD="yum"
        $pm_CMD -y install epel-release
    fi
    if [[ -f /usr/bin/apt ]]; then
        pm_CMD="apt"
    fi
    if [[ -f /bin/systemctl ]]; then
        systemd=true
    fi
    
else
    echo -e " 哈哈……这个 ${red}辣鸡脚本${none} 只支持CentOS7+及Ubuntu14+ ${yellow}(-_-) ${none}" && exit 1
fi
function service_Cmd(){
    if [[ $systemd ]]; then
        systemctl $1 $2
    else
        service $2 $1
    fi
}

function files_syncdown(){
    # 从百度云盘下载到本地
    cd $dir_syncdown
    bypy syncdown
}

function files_syncup(){
    # 重新上传到百度云盘
    cd $dir_syncup
    bypy syncup
}

function set_passwd_lanzou(){
    # 设置蓝奏密码
    # 读
    # cmd="select count(*) from tempdb.tb_tmp"
    # cnt=$(mysql -uroot -p123456 -s -e "${cmd}")
    # echo "Current count is : ${cnt}"
    
    # 写
    #!/bin/bash
    # i=1
    # while [ $i -le 100000000 ]
    # do
    #     mysql -uroot -p123456 test -e "insert into student (name,createTime) values ('student$i',NOW());"
    #     i=$(($i+1))
    #     sleep 6
    # done
}

function files_dir_filter(){
    # 判断路径
    # 固定四级目录规则：/一级分类目录/二级分类目录/三级分类目录/资源目录/资源压缩包.{zip,7z,rar,gz}
    # 资源全部放置在四级目录之下，本shell与一级分类一起放在根目录执行
    pwd_path=`pwd`
    
    if [[ $1 == /* ]] ;then
        unzip_target=$1"_unzip"
    else
        unzip_target=$pwd_path"/"$1"_unzip"
    fi
    
}

function files_zip(){
    # 压缩成.zip包
    echo "----zip file----"
    pwd_path=`pwd`
    
    if [[ $1 == /* ]] ;then
        zip_target=$1"_zip"
    else
        zip_target=$pwd_path"/"$1"_zip"
    fi
    
    echo "将 $1 目录下的文件逐个压缩，压缩后存放到路径 $zip_target 中"
    if [ ! -d $zip_target ]; then
        mkdir -p $zip_target
    fi
    
    function zip_file(){
        for file in `ls $1`
        do
            if [ -d $1"/"$file ]; then
                cd $1
                tar zcvf $zip_target"/"$file.tar.gz $file
                cd $pwd_path
            fi
        done
    }
    zip_file $1
}

function files_unzip(){
    # 解压.zip格式
    echo " ----unzip file---- "
    
    echo "将 $1 目录下的压缩文件逐个解压，解压后存放到目录 $unzip_target 中"
    if [ ! -d $unzip_target ]; then
        mkdir -p $unzip_target
    fi
    
    function unzip_file(){
        for file in `ls $1`
        do
            if [[ $1"/"$file == *tar.gz ]]; then
                tar zxvf $1"/"$file -C $unzip_target
            fi
        done
    }
    unzip_file $1
}
function files_unrar(){
    # 解压.rar格式
    echo " ----unrar file---- "
}
function files_un7z(){
    # 解压.7z格式
    echo " ----un7z file---- "
    7za x
}

function install_bypy(){
    # 安装bypy：https://github.com/houtianze/bypy
    if [[ bypy -V ]]; then
        echo -e " 很好，bypy ${yellow}已经安装过了 ${none}"
    else
        pip install bypy
    fi
}

function install_lanzouCloud_CMD(){
    # 安装 lanzouCloud_CMD：https://github.com/zaxtyson/LanZouCloud-CMD，需要 Python 3.8+ 环境
    if [[ -d $lanzouCloud_CMD_path ]]; then
        echo -e " 很好，lanzouCloud_CMD ${yellow}已经安装过了 ${none}"
    else
        pip install requests requests-toolbelt
        git clone -b master https://github.com/zaxtyson/LanZouCloud-CMD.git $lanzouCloud_CMD_path
    fi
}

function install_base(){
    if [[ -f /usr/auto_files.log ]]; then
        echo -e " 已经安装过，不再安装，需要重新安装请删除${yellow} /usr/auto_files.log ${none}"
    else
        $pm_CMD  -y install zip unzip p7zip git gcc gcc++
        # install unrar
        src_unrar='https://www.rarlab.com/rar/unrarsrc-5.9.4.tar.gz'
        tar xzf unrarsrc-5.9.4.tar.gz && cd unrar
        make && make install
        rm -rf unrar unrarsrc-5.9.4.tar.gz
        install_python3 && install_pip
        echo "done">/usr/auto_files.log
        echo -e " ----基础软件安装完成---- "
    fi
}

function install_python3(){
    # 升级python3
    if [[ python3 -V ]]; then
        echo -e " 很好，python3 ${yellow}已经升级安装过了 ${none}"
    else
        $pm_CMD -y install openssl-static zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel
        $pm_CMD groupinstall "Development tools"
        wget --no-check-certificate https://www.python.org/ftp/python/$python3_ver/Python-$python3_ver.tgz && tar zxf Python-$python3_ver.tgz && cd Python-$python3_ver
        ./configure --prefix=/usr/local/python3 && make && make install
        ln -s /usr/local/python3/bin/python3 /usr/bin/python3
        cd ../ && rm -rf Python-$python3_ver
    fi
}

function install_pip(){
    if [[ pip -V ]]; then
        echo -e " 很好，pip ${yellow}已经安装过了 ${none}"
    else
        wget https://bootstrap.pypa.io/get-pip.py
        python get-pip.py
        sed -i '|^.*python3/bin*|d' /etc/profile
        sed -i '$a\export PATH=\"/usr/local/python3/bin:$PATH\"' /etc/profile
        source /etc/profile
        rm -f get-pip.py
    fi
}

function set_cron(){
    # 添加系统定时任务
    sed -i '|^.*ntpdate*|d' /etc/crontab
    sed -i '$a\0 */1 * * * root ntpdate cn.pool.ntp.org >> /dev/null 2>&1' /etc/crontab
    service_Cmd restart crond
}

# 下面 `getopt ab:c:d` "$@" 中的 abcd 分别代表四个选项，后面带有冒号的表示选项需要参数值
GETOPTOUT=`getopt ib:c:d "$@"`
set -- $GETOPTOUT
while [ -n "$1" ]
do
    case $1 in
        -i)
            install_base
            install_python3
            install_pip
            install_bypy
            install_lanzouCloud_CMD
            echo "软件环境初始化安装完成"
            shift
        ;;
        -b)
            echo "发现 -b 选项"
            echo "-b 选项的参数值是：$2"
            shift
        ;;
        -c)
            echo "发现 -c 选项"
            echo "-c 选项的参数值是：$2"
            shift
        ;;
        -d)
            echo "发现 -d 选项"
        ;;
        --)
            shift
            break
        ;;
        *)
            echo "未知选项:"$1""
        ;;
    esac
    shift
done