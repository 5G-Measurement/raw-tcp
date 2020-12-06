#!/bin/sh

cd "$(dirname "$0")" || exit

if iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP; then
    iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
fi
