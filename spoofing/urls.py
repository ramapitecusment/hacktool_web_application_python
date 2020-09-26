"""HackTool URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name = 'index'),
    path('arp_spoofing/', views.arp_spoofing, name = 'arp_spoofing'),
    path('dns_spoofing/', views.dns_spoofing, name = 'dns_spoofing'),
    path('packet_sniffing/', views.packet_sniffing, name='packet_sniffing'),
    path('code_injector/', views.code_injector, name='code_injector'),
    path('replace_downloads/', views.replace_downloads, name='replace_downloads'),
]
