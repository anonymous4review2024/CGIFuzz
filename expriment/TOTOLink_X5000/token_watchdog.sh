#!/bin/sh

while true; do
    # 检查 /tmp/cookie_key 文件是否存在以及内容是否符合要求
    if [ -f "/tmp/cookie_key" ]; then
        content=$(cat /tmp/cookie_key)
        if [ "$content" != "62b4ac27510732d94d69ddea71d2de4f" ]; then
            echo -n "62b4ac27510732d94d69ddea71d2de4f" > /tmp/cookie_key
        fi
    else
        echo -n "62b4ac27510732d94d69ddea71d2de4f" > /tmp/cookie_key
    fi

    # 使用 echo -n 和命令替换来写入时间戳，不添加换行符
    echo -n $(date +%s) > /tmp/token_uptime

    # 等待1秒
    sleep 1
done
