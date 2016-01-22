

# Tasks
* [X] CP templates
* [X] Capture test traffic
* [ ] Setup network filtering
  * [X] block https for everybody
  * [ ] implement fine grain network filter for target IP
* [ ] IP/MAC database
  * [ ] keep track of allowed hosts
* [ ] Hijack DNS responses
  * [X] respond with scapy
  * [ ] drop requests with nfqueue
  * [ ] ake AAAA queries
* [ ] Templates for the Captive Portal
  * [X] static template support
  * [ ] create example templates for well known captive portals
  * [ ] scrape custom webpage to create a template


# Links
## Python 
* [scapy/scapy/layers/dns.py](https://github.com/jwiegley/scapy/blob/master/scapy/layers/dns.py)
* [DanMcInerney/dnsspoof](https://github.com/DanMcInerney/dnsspoof)

## MITMf related functions
* [inject.py](https://github.com/byt3bl33d3r/MITMf/blob/master/plugins/inject.py)
* [core/servers/HTTP.py#L40](https://github.com/byt3bl33d3r/MITMf/blob/master/core/servers/HTTP.py#L40)
* [plugins/ferretng.py#L78](https://github.com/byt3bl33d3r/MITMf/blob/master/plugins/ferretng.py#L78)

## Captive Portal
* [Network Portal Detection](https://www.chromium.org/chromium-os/chromiumos-design-docs/network-portal-detection)
* [Distinguish between Wi-Fi Captive portal and MitM attack](https://security.stackexchange.com/questions/87320/distinguish-between-wi-fi-captive-portal-and-mitm-attack)
* [ARP MiTM Captive Portal](https://github.com/CroweCybersecurity/MiTM-CaptivePortal/)
* [CaptivePortal - Personal Telco Project](https://personaltelco.net/wiki/CaptivePortal)
* [PortalSoftware - Personal Telco Project](https://personaltelco.net/wiki/PortalSoftware)
* [How does external captive portal with XML API server...](http://community.arubanetworks.com/t5/Controller-Based-WLANs/How-does-external-captive-portal-with-XML-API-server-work-with/ta-p/184600)

# Improvements
## Replace pyinotify with watchdog (*unix)
* [Replaced pyInotify with watchdog, not tested on osX and windows though](https://github.com/raphdg/baboon/commit/2c115da63dac16d0fbdc9b45067d0ab0960143ed)

