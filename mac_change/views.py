from django.shortcuts import render

def index(request):
    my_dict = {}
    return render(request, 'mac_change.html', context = my_dict)
