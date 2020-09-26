from django.shortcuts import render

def command_line(request):
    my_dict = {}
    return render(request, 'command_line.html', context = my_dict)


