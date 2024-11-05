#!/bin/sh
#This script redirects traffic coming from LAN (and ONLY from LAN) to Xray via TPROXY.
#Traffic originated from the router itself is unaffected in any way.
#Therefore things like DNS-requests from the router itself are not redirected to Xray by this script and can be compromised by ISP.
#To specifically redirect DNS-requests on OpenWrt it is much easier to simply forward them to Xray using feature in dnsmasq itself then creating special filter rules in OUTPUT chain.

# To use this script you have do the following:
#   0. This script uses 'iptables' to define packet filtering rules and redirect traffic via TPROXY. iptables are no longer supported by OpenWrt so if you really need to use them install 'iptables-nft', 'iptables-mod-filter' and 'iptables-mod-tproxy' for TPROXY
#   1. Create custom routing table (in "/etc/iproute2/rt_tables") with the corresponding number/name
#   2. Put this file into /usr/bin/xray-tproxy.sh
#   3. Make script executable: chmod +x /usr/bin/xray-tproxy.sh
#   4. To run it as a service setup 'xray-tproxy' (follow instructions from there)
#   5. To view the log use: logread | grep xray-tproxy
#   6. You can use arguments to start/stop/check proxification (look values at the end of this file)

# Define parameters
ROUTING_TABLE=252               #Custom routing table for Xray
ROUTING_MARK=252                #Firewall mark of the packets routed to Xray
LOG_ENABLE=true                 #Set to false to disable logging

# Define networks
ipaddr=$(uci get network.lan.ipaddr) && netmask=$(uci get network.lan.netmask) && cidr=$(echo "$netmask" | awk -F. '{for(i=1;i<=4;i++) s=s+($i==255?8:($i==254?7:($i==252?6:($i==248?5:($i==240?4:($i==224?3:($i==192?2:($i==128?1:0)))))))); print s}')
SUBNET_LAN="$ipaddr/$cidr"                                          #LAN subnet (network behind the router)
SUBNET_DIRECT=$(ip address | grep -w "inet" | awk '{print $2}')     #all subnets to which router has direct connection
SUBNET_PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"            #private networks
SUBNET_EXEMPT_TO=""                                                 #networks exempted from Xray that traffic going into
SUBNET_EXEMPT_FROM=""                                               #networks exempted from Xray that traffic originating from

# Function to enable traffic proxying into Xray
proxy_start() {
    #1. Policy routing setup
    ip rule add fwmark $ROUTING_MARK table $ROUTING_TABLE       #Add a policy routing rule. Any packet with a firewall mark (fwmark) of <ROUTING_MARK> should use routing table <ROUTING_TABLE>
    ip route add local 0.0.0.0/0 dev lo table $ROUTING_TABLE    #Add a local route to the routing table <ROUTING_TABLE> for the entire IPv4 address range. All traffic marked for table <ROUTING_TABLE> will be routed locally to the loopback interface (lo).

    #2. Traffic redirection to Xray from LAN
    #   Create a new chain called XRAY_LAN in the mangle table, which is responsible for packet alteration.
    iptables -t mangle -N XRAY_LAN
    #   Exempt specific traffic from being redirected to Xray
    iptables -t mangle -A XRAY_LAN ! -s $SUBNET_LAN -j RETURN                                           #sourced from outside of LAN (restrain access from WAN side)
    for subnet in $SUBNET_DIRECT; do iptables -t mangle -A XRAY_LAN -d $subnet -j RETURN; done          #destined to all subnets which router has direct connection to
    for subnet in $SUBNET_PRIVATE; do iptables -t mangle -A XRAY_LAN -d $subnet -j RETURN; done         #destined to private networks
    iptables -t mangle -A XRAY_LAN -d 127.0.0.0/8 -j RETURN                                             #destined to loopback
    iptables -t mangle -A XRAY_LAN -d 224.0.0.0/4 -j RETURN                                             #destined to multicast
    iptables -t mangle -A XRAY_LAN -d 255.255.255.255/32 -j RETURN                                      #destined to broadcast
    for subnet in $SUBNET_EXEMPT_TO; do iptables -t mangle -A XRAY_LAN -d $subnet -j RETURN; done       #destined to user exclusion
    for subnet in $SUBNET_EXEMPT_FROM; do iptables -t mangle -A XRAY_LAN -s $subnet -j RETURN; done     #sourced from user exclusion
    #   Redirect packets to the Xray instance on the loopback IP 127.0.0.1 and port 12345, using TPROXY for transparent proxying. Packets are also marked with <ROUTING_MARK> to use the policy routing set up in step 1.
    iptables -t mangle -A XRAY_LAN -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark $ROUTING_MARK   #UDP
    iptables -t mangle -A XRAY_LAN -p udp -j TPROXY --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark $ROUTING_MARK   #TCP
    #   Append XRAY_LAN chain into the PREROUTING chain so that all incoming traffic to the router goes through the XRAY_LAN rules
    iptables -t mangle -A PREROUTING -j XRAY_LAN
}

# Function to disable traffic proxying into Xray
proxy_stop() {
    #1. Clear iptables rules
    iptables -t mangle -D PREROUTING -j XRAY_LAN
    iptables -t mangle -F XRAY_LAN
    iptables -t mangle -X XRAY_LAN

    #2. Remove policy routing
    ip rule del fwmark $ROUTING_MARK table $ROUTING_TABLE
    ip route del local 0.0.0.0/0 dev lo table $ROUTING_TABLE
}

# Function to check proxification status
proxy_state() {
    if iptables -t mangle -C PREROUTING -j XRAY_LAN >/dev/null 2>&1; then
        echo "true"  # Proxification is started
    else
        echo "false" # Proxification is stopped
    fi
}

# Function to log messages
log_message() {
    local message="$1"
    if [ $LOG_ENABLE = true ]; then
        logger -t xray-tproxy "$message"
        #echo "$(date +"%Y-%m-%d @ %H:%M:%S") $message"
    fi
}

# Handle command-line arguments
status=$(proxy_state)
case "$1" in
    -s) #stop proxification
        if [ "$status" = "true" ]; then
            log_message "Stopping proxification to Xray via TPROXY."
            proxy_stop
        else
            log_message "Proxification is already stopped, skipping."
        fi
        ;;
    -c) #check proxification status
        if [ "$status" = "true" ]; then
            echo "Proxification is currently enabled."
        else
            echo "Proxification is currently disabled."
        fi
        ;;
    *) #no arguments = start proxification
        if [ "$status" = "true" ]; then
            log_message "Proxification is already started, skipping."
        else
            log_message "Starting proxification to Xray via TPROXY."
            proxy_start
        fi
        ;;
esac
