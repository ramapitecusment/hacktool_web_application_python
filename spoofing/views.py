from django.shortcuts import render

def index(request):
    my_dict = {}
    return render(request, 'index.html', context = my_dict)

def arp_spoofing(request):
    my_dict = {}
    return render(request, 'arp_spoofing.html', context = my_dict)

def packet_sniffing(request):
    my_dict = {}
    return render(request, 'packet_sniffing.html', context = my_dict)

def dns_spoofing(request):
    my_dict = {}
    return render(request, 'dns_spoofing.html', context = my_dict)

def code_injector(request):
    my_dict = {}
    return render(request, 'code_injector.html', context = my_dict)

def replace_downloads(request):
    my_dict = {}
    return render(request, 'replace_downloads.html', context = my_dict)