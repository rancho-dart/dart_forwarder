OUTSIDE_IFCE=ens37
INSIDE_IFCE=ens38
PRIVATE_NETWORK=10.100.0.0/24
PSEUDO_POOL=198.18.0.0/15

# 排除源端口为 55847 的 TCP/UDP 报文
sudo iptables -t nat -A POSTROUTING -p udp --sport 55847 -j RETURN
# 排除目标端口为 55847 的 TCP/UDP 报文
sudo iptables -t nat -A POSTROUTING -p udp --dport 55847 -j RETURN

iptables -t nat -A POSTROUTING -o $OUTSIDE_IFCE -s $PRIVATE_NETWORK -j MASQUERADE

iptables -A FORWARD -i $INSIDE_IFCE -o $OUTSIDE_IFCE -s $PRIVATE_NETWORK ! -d $PSEUDO_POOL -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $OUTSIDE_IFCE -o $INSIDE_IFCE                     -m conntrack --ctstate     ESTABLISHED,RELATED -j ACCEPT

