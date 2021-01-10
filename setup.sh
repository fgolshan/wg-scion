./wireguard wg0 ;
ip -4 address add 10.8.1.1/24 dev wg0 ;
ip link set mtu 1420 up dev wg0 ;
sudo nc -U /var/run/wireguard/wg0.sock < interface.conf ;
wg
