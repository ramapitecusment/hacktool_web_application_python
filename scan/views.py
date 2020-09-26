from django.shortcuts import render

def network_scan(request):
    my_dict = {}
    return render(request, 'network_scan.html', context = my_dict)

def advanced_network_scan(request):
    my_dict = {}
    return render(request, 'advanced_network_scan.html', context = my_dict)

def web_application_scan(request):
    my_dict = {}
    return render(request, 'web_application_scan.html', context = my_dict)

def xss_scan(request):
    my_dict = {}
    return render(request, 'xss_scan.html', context = my_dict)

def sql_injection_scan(request):
    my_dict = {}
    return render(request, 'sql_injection_scan.html', context = my_dict)

def page_bruteforce(request):
    my_dict = {}
    return render(request, 'page_bruteforce.html', context = my_dict)

def md5_encrypt(request):
    my_dict = {}
    return render(request, 'md5_encrypt.html', context = my_dict)

def md5_decrypt(request):
    my_dict = {}
    return render(request, 'md5_decrypt.html', context = my_dict)