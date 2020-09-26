from channels.generic.websocket import AsyncWebsocketConsumer
from re import findall, search
from subprocess import check_output, call
from json import dumps, loads

class MacChange(AsyncWebsocketConsumer):

    async def connect(self):
         await self.accept()

    async def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    async def receive(self, text_data):
        text_data_json = loads(text_data)

        if "reset_mac" in text_data:
            result = check_output(["ethtool", "-P", "eth0"], encoding="UTF-8")
            mac_address = findall(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", result)[0]
            await self.send_mac("eth0", mac_address)
        elif "interface" in text_data and "new_mac" in text_data and len(text_data_json["interface"]) == 4 and len(text_data_json["new_mac"]) == 17:
            print("receive", text_data_json["interface"], text_data_json["new_mac"])

            await self.send_mac(text_data_json["interface"], text_data_json["new_mac"])

        else:
            await self.send(text_data=dumps({
                'error': "Please, fill all fields correctly"
            }))

    async def change_mac(self, interface, new_mac):
        await self.send(text_data=dumps({
            'message': "[+] Changing MAC address for " + interface + " to " + new_mac
        }))
        print("[+] Changing MAC address for " + interface + " to " + new_mac)

        call(["ifconfig", interface, "down"])
        call(["ifconfig", interface, "hw", "ether", new_mac])
        call(["ifconfig", interface, "up"])

    async def get_current_mac(self, interface):
        ifconfig_result = check_output(["ifconfig", interface], encoding="UTF-8")
        mac_address_search_result = search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

        if mac_address_search_result:
            return mac_address_search_result.group(0)
        else:
            await self.send(text_data=dumps({
                'error': "[-] Could not read MAC address "
            }))
            print("[-] Could not read MAC address ")

    async def send_mac(self, interface="eth0", new_mac="04:D4:C4:E6:E4:F3"):
        current_mac =  str(await self.get_current_mac(interface))
        if current_mac != "None":
            await self.send(text_data=dumps({
                'message': "Current MAC: " + current_mac
            }))
            print("Current MAC: " + current_mac)
            await self.change_mac(interface, new_mac)

        current_mac = await self.get_current_mac(interface)
        print(current_mac, new_mac)
        if str(current_mac).upper() == new_mac.upper():
            await self.send(text_data=dumps({
                'message': "[+] MAC address was successfylly changed to " + str(current_mac)
            }))
        else:
            await self.send(text_data=dumps({
                'error': "[-] MAC address did not get changed."
            }))
