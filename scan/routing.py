from . import consumers
from django.urls import path

websocket_urlpatterns = [
    # re_path(r'ws/chat/(?P<room_name>\w+)/$', consumers.ChatConsumer),
    path('scan/network_scan/', consumers.NetworkScan),
    path('scan/advanced_network_scan/', consumers.AdvancedNetworkScan),
    path('scan/web_application_scan/', consumers.WebApplicationScan),
    path('scan/xss_scan/', consumers.XssScan),
    path('scan/sql_injection_scan/', consumers.SQLInjectionScan),
    path('scan/page_bruteforce/', consumers.PageBruteforce),
    path('scan/md5_encrypt/', consumers.MD5Encrypt),
    path('scan/md5_decrypt/', consumers.MD5Decrypt),
]