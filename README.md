# xray-tproxy
This script redirects traffic from LAN (and ONLY from LAN) to Xray via TPROXY. Traffic originated from the router itself is unaffected in any way. Therefore things like DNS-requests from the router itself are not redirected to Xray by this script and can be compromised by ISP. To specifically redirect DNS-requests on OpenWrt it is much easier to simply forward them to Xray using feature in dnsmasq itself than hijacking them via filter rules in OUTPUT chain.

- `xray-tproxy_nftabes.sh` - version for nftables;
- `xray-tproxy_iptabes.sh` - version for iptables (legacy);
- `xray-tproxy` - service for OpenWrt;
- `xray_config.json` - minimum config for Xray to use with all of these.

### Configure OpenWrt to exclusively use DNS provided by Xray
- Remove DNS servers provided by ISP to the WAN interface:

```
Network -> Interfaces
    Interfaces
        wan -> Edit
            Advanced Settings
                Use DNS servers advertised by peer: false
            Save
Save & Apply
```
- Force OpenWrt's DNS resolver (dnsmasq) to use Xray:
```
Network -> DHCP and DNS
    Forwards
        DNS Forwards: 127.0.0.1#5353
Save & Apply
```
