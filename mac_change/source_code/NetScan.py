from channels.generic.websocket import AsyncWebsocketConsumer
import json, subprocess, re
import scapy.all as scapy

class NetScan(AsyncWebsocketConsumer):

    async def connect(self):
         await self.accept()

    async def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)

        if "range" in text_data:
            await self.print_result(await self.scan(text_data_json["range"]))

        else:
            await self.send(text_data=json.dumps({
                'error': "Please, fill all fields correctly :)"
            }))

    async def scan(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = []

        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)

        return clients_list

    async def print_result(self, results_list):
        await self.send(text_data=json.dumps({
            'net_scan_result': "IP\t\t\tMAC Address\n------------------------------------------"
        }))

        for client in results_list:
            await self.send(text_data=json.dumps({
                'net_scan_result': client["ip"] + "\t\t" + client["mac"]
            }))