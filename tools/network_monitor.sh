#!/bin/bash

# 指定要监视的网卡名称
INTERFACE="eth0"

# 获取当前时间戳（以秒为单位）
CURRENT_TIME=$(date +%s)

# 计算 10 分钟前的时间戳（以秒为单位）
TEN_MINUTES_AGO=$(date -d "10 minutes ago" +%s)

# 获取 10 分钟内指定网卡的出站流量（以字节为单位）
OUTGOING=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)

# 将出站流量转换为 GB，并保留三位小数
OUTGOING_GB=$(printf "%.3f" $(echo "scale=3; $OUTGOING / 1024 / 1024 / 1024" | bc))

# 设置阈值（以 GB 为单位）
THRESHOLD=20

# 检查 10 分钟内出站流量是否超过阈值
if (( $(echo "$OUTGOING_GB > $THRESHOLD" | bc -l) )); then
    echo "[$INTERFACE] 过去 10 分钟内的出站流量为: $OUTGOING_GB GB，超过 $THRESHOLD GB！执行关机命令..."
    # 执行关机命令
    /usr/sbin/shutdown -h now
else
    echo "[$INTERFACE] 过去 10 分钟内的出站流量为: $OUTGOING_GB GB，未超过 $THRESHOLD GB。"
fi