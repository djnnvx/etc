#!/bin/bash

tail -n +2 /proc/net/tcp | while read -r _ local remote _; do
    ip_local=$(echo ${local%:*} | sed 's/../0x& /g' | awk '{printf "%d.%d.%d.%d", $4, $3, $2, $1}')
    ip_remote=$(echo ${remote%:*} | sed 's/../0x& /g' | awk '{printf "%d.%d.%d.%d", $4, $3, $2, $1}')
    port_local=$((16#${local##*:}))
    port_remote=$((16#${remote##*:}))

    echo "$ip_local:$port_local -> $ip_remote:$port_remote"
done

