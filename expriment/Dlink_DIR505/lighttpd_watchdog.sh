#!/bin/sh

while true; do
    # 使用 pgrep 检查 lighttpd 进程是否存在
    if ! pgrep -f "/usr/sbin/lighttpd -f /tmp/lighttpd.conf" > /dev/null; then
        echo "lighttpd process not found, starting it..."
        /usr/sbin/lighttpd -f /tmp/lighttpd.conf
    else
        echo "lighttpd process is running."
    fi
    # 等待 5 秒
    sleep 5
done
