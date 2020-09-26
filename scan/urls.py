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
    path('network_scan/', views.network_scan, name = 'network_scan'),
    path('advanced_network_scan/', views.advanced_network_scan, name = 'advanced_network_scan'),
    path('web_application_scan/', views.web_application_scan, name = 'web_application_scan'),
    path('xss_scan/', views.xss_scan, name = 'xss_scan'),
    path('sql_injection_scan/', views.sql_injection_scan, name = 'sql_injection_scan'),
    path('page_bruteforce/', views.page_bruteforce, name = 'page_bruteforce'),
    path('md5_encrypt/', views.md5_encrypt, name = 'md5_encrypt'),
    path('md5_decrypt/', views.md5_decrypt, name = 'md5_decrypt'),
]
