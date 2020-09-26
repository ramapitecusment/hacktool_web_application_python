from . import consumers
from django.urls import path

websocket_urlpatterns = [
    # re_path(r'ws/chat/(?P<room_name>\w+)/$', consumers.ChatConsumer),
    path('spoofing/arp_spoofing/', consumers.ARPSpoof),
    path('spoofing/packet_sniffing/', consumers.PacketSniffing),
    path('spoofing/dns_spoofing/', consumers.DNSSpoof),
    path('spoofing/code_injector/', consumers.CodeInjector),
    path('spoofing/replace_downloads/', consumers.ReplaceDownloads),
]