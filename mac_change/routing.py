# mac_change/routing.py
from django.urls import re_path
from . import consumers
from django.urls import path

websocket_urlpatterns = [
    # re_path(r'ws/chat/(?P<room_name>\w+)/$', consumers.ChatConsumer),
    path('mac_change/', consumers.MacChange),
    path('', consumers.MacChange)
]