#!/bin/bash

# 禁止自动更新和自动升级
echo "禁用自动更新和自动升级..."
sudo systemctl stop apt-daily.timer
sudo systemctl disable apt-daily.timer
sudo systemctl stop apt-daily-upgrade.timer
sudo systemctl disable apt-daily-upgrade.timer

# 禁用Ubuntu更新通知服务
echo "禁用更新通知服务..."
sudo systemctl stop update-notifier
sudo systemctl disable update-notifier

# 禁用远程传感器（如摇杆、蓝牙、NFC等）
echo "禁用远程传感器支持..."
sudo systemctl stop bluetooth
sudo systemctl disable bluetooth
sudo systemctl stop iio-sensor-proxy
sudo systemctl disable iio-sensor-proxy
sudo systemctl stop wpa_supplicant
sudo systemctl disable wpa_supplicant

# 禁用虚拟内存（交换空间）
echo "禁用虚拟内存（交换空间）..."
# 禁用当前的swap空间
sudo swapoff -a

# 永久禁用交换空间
echo "swapoff -a" | sudo tee -a /etc/rc.local
sudo chmod +x /etc/rc.local

# 从 /etc/fstab 删除 swap 相关配置
sudo sed -i '/swap/d' /etc/fstab

# 删除交换空间文件
sudo rm -f /swapfile

# 禁用桌面通知（如果你不需要桌面通知）
echo "禁用桌面通知..."
gsettings set org.gnome.desktop.notifications show-banners false

# 禁用Snap包支持
echo "禁用Snap包支持..."
sudo systemctl stop snapd.service
sudo systemctl disable snapd.service
sudo rm -rf /var/cache/snapd/

# 禁用部分不必要的系统服务
echo "禁用不必要的服务..."
sudo systemctl disable apport
sudo systemctl stop apport
sudo systemctl disable whoopsie
sudo systemctl stop whoopsie

# 删除不必要的软件包
echo "删除不必要的包..."
sudo apt-get remove --purge ubuntu-web-launchers thunderbird* libreoffice* gnome-games* aisleriot* gnome-mines* gnome-mahjongg* 
sudo apt-get autoremove --purge
sudo apt-get clean

# 删除自动安装的无用依赖包
echo "删除无用的依赖包..."
sudo apt-get autoremove --purge

# 禁用服务日志
echo "禁用服务日志..."
# 禁用系统日志服务
sudo systemctl stop systemd-journald
sudo systemctl disable systemd-journald

# 清理APT缓存和日志
echo "清理APT缓存和日志..."
sudo rm -rf /var/cache/apt/*

# 禁用不需要的用户账户（如Ubuntu默认账户）
echo "禁用不必要的用户账户..."
sudo usermod -L ubuntu

# 配置永久禁用虚拟内存（通过 /etc/fstab 和 /etc/rc.local）
echo "配置永久禁用虚拟内存..."
# 将 swapoff 配置写入 /etc/rc.local
echo "swapoff -a" | sudo tee -a /etc/rc.local
# 确保 rc.local 可执行
sudo chmod +x /etc/rc.local

# 删除 /swapfile 文件并移除 /etc/fstab 中的 swap 配置
echo "移除交换文件和配置..."
sudo rm -f /swapfile
sudo sed -i '/swap/d' /etc/fstab

# 配置服务禁用（如果有服务需要禁用）
echo "配置服务禁用..."
# 可以通过创建自定义 systemd 单元文件来禁用不需要的服务，举例如下：
echo "[Unit]
Description=Disable Unwanted Service

[Service]
ExecStart=/bin/true
RemainAfterExit=true

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/disable-unwanted.service
sudo systemctl daemon-reload
sudo systemctl enable disable-unwanted.service

# 设置加密DNS（使用 systemd-resolved 配置 DoH 或 DoT）
echo "配置加密DNS..."

# 通过修改 systemd-resolved 配置文件来启用 DNS over HTTPS (DoH)
echo "DNS=1.1.1.1 1.0.0.1" | sudo tee -a /etc/systemd/resolved.conf
echo "DNSOverTLS=yes" | sudo tee -a /etc/systemd/resolved.conf
echo "FallbackDNS=8.8.8.8 8.8.4.4" | sudo tee -a /etc/systemd/resolved.conf

# 重启 systemd-resolved 服务使更改生效
sudo systemctl restart systemd-resolved

# 更新系统的 DNS 配置，使用 systemd-resolved 提供的加密DNS
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# 配置系统的 DNS 配置使得每次重启时都能使用加密的DNS
echo "nameserver 127.0.0.1" | sudo tee -a /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

# 配置代理（HTTP、HTTPS 和 SOCKS5 代理）
echo "配置代理设置..."
export http_proxy="http://192.168.123.129:2080"
export https_proxy="http://192.168.123.129:2080"
export socks_proxy="socks5://192.168.123.129:2080"

# 让代理设置永久生效
echo "http_proxy=http://192.168.123.129:2080" | sudo tee -a /etc/environment
echo "https_proxy=http://192.168.123.129:2080" | sudo tee -a /etc/environment
echo "socks_proxy=socks5://192.168.123.129:2080" | sudo tee -a /etc/environment

# 配置 apt 代理设置（不修改源，仅配置代理）
echo "配置APT代理..."
echo "Acquire::http::Proxy \"http://192.168.123.129:2080\";" | sudo tee -a /etc/apt/apt.conf.d/95proxies
echo "Acquire::https::Proxy \"http://192.168.123.129:2080\";" | sudo tee -a /etc/apt/apt.conf.d/95proxies

# 更新包列表
echo "更新包列表..."
sudo apt-get update

# 安装基础开发环境：git, curl, gcc, make, build-essential
echo "安装基础开发环境..."
sudo apt-get install -y git curl gcc make build-essential

# 安装 C 语言编译环境：gcc 和相关工具
echo "安装 GCC 编译器和 C 语言开发工具..."
sudo apt-get install -y gcc g++ clang

# 安装调试工具（gdb等）
echo "安装调试工具..."
sudo apt-get install -y gdb valgrind

# 安装常用的网络工具
echo "安装常用网络工具..."
sudo apt-get install -y net-tools

# 安装基本编辑器：vim, nano
echo "安装文本编辑器..."
sudo apt-get install -y vim nano

# 安装其他基础工具：wget, unzip, zip, tar
echo "安装其他常用工具..."
sudo apt-get install -y wget unzip zip tar

# 配置 git 全局用户名和邮箱
echo "配置 Git..."
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# 配置 curl 默认代理
echo "配置 curl 默认代理..."
echo "proxy = \"http://192.168.123.129:2080\"" | sudo tee -a ~/.curlrc

# 完成
echo "基础开发环境安装完成，代理设置已生效！"


#!/bin/bash

# 配置代理（HTTP、HTTPS 和 SOCKS5 代理）
echo "配置代理设置..."
export http_proxy="http://192.168.123.129:2080"
export https_proxy="http://192.168.123.129:2080"
export socks_proxy="socks5://192.168.123.129:2080"

# 让代理设置永久生效
echo "http_proxy=http://192.168.123.129:2080" | sudo tee -a /etc/environment
echo "https_proxy=http://192.168.123.129:2080" | sudo tee -a /etc/environment
echo "socks_proxy=socks5://192.168.123.129:2080" | sudo tee -a /etc/environment

# 配置 apt 代理设置（不修改源，仅配置代理）
echo "配置APT代理..."
echo "Acquire::http::Proxy \"http://192.168.123.129:2080\";" | sudo tee -a /etc/apt/apt.conf.d/95proxies
echo "Acquire::https::Proxy \"http://192.168.123.129:2080\";" | sudo tee -a /etc/apt/apt.conf.d/95proxies

# 更新包列表
echo "更新包列表..."
sudo apt-get update

# 安装基础开发环境：git, curl, gcc, make, build-essential
echo "安装基础开发环境..."
sudo apt-get install -y git curl gcc make build-essential

# 安装 C 语言编译环境：gcc 和相关工具
echo "安装 GCC 编译器和 C 语言开发工具..."
sudo apt-get install -y gcc g++ clang

# 安装调试工具（gdb等）
echo "安装调试工具..."
sudo apt-get install -y gdb valgrind

# 安装常用的网络工具
echo "安装常用网络工具..."
sudo apt-get install -y net-tools

# 安装基本编辑器：vim, nano
echo "安装文本编辑器..."
sudo apt-get install -y vim nano

# 安装其他基础工具：wget, unzip, zip, tar
echo "安装其他常用工具..."
sudo apt-get install -y wget unzip zip tar

# 配置 git 全局用户名和邮箱
echo "配置 Git..."
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# 配置 curl 默认代理
echo "配置 curl 默认代理..."
echo "proxy = \"http://192.168.123.129:2080\"" | sudo tee -a ~/.curlrc

# 完成
echo "基础开发环境安装完成，代理设置已生效！"



