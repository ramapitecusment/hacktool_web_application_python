# 

The convenience of using the WebSocket Protocol is provided by the ability to send packets 
and HTTP requests in both directions. This technology is widely used among web 
applications that actively use constant data transportation and processing, such as 
trading platforms, chats, and online games.

Django Channels extends the capabilities of the HTTP Protocol and brings Protocol support 
for web sockets, chats, Internet of things, and more. Channels uses the successor to **WSGI**, 
which is called **ASGI** (Asynchronous Server Gateway Interface) and supports both synchronous 
and asynchronous code, as well as full backward compatibility with WSGI. In order for the 
client to connect via the ASI interface, it sends a request to the server to make sure that 
the machine supports the WebSocket Protocol.
```
var loc = window.location;
var wsStart = 'ws://';
if (loc.protocol == 'https:') {
  wsStart = 'wss://';
}
```
To process a web socket connection, you need to install the **Django framework** and the **Django** 
**Channels** library. However, before installing these packages, the official documentation 
recommends using a virtual Python development environment, such as **virtualenv**. This is 
extremely necessary, because if different projects use different versions of libraries, 
there may be serious compatibility problems. The virtual environment also allows you to 
easily update the necessary packages without any fear that project X will affect project 
Y in any way, which is ensured by complete isolation between these environments.

To use an isolated environment, you must first download it using the command: 
```
pip3 install virtualenv
```
Next, to create a virtual environment, enter the command:
```
python3-m venv ‘name’
```
and to activate it, enter the following line source:
```
‘name’/bin/activate.
```

To install Django and Django Channels, enter the following commands in the console:
```
python3 -m pip install Django
pip install channels
```
After successful installation, you need to create a project using 
```
django-admin startproject ‘project name’
```
A file will be generated in this directory **manage.py** and the project with the same name 
as specified by the previous command. This project will contain Python files **__init__.py**
, **settings.py**, **urls.py** and **wsgi.py** required to run the web application. 
Файл **__init__.py** serves as a pointer for Python to start the application from this file; 
**settings.py** contains the full settings and configurations that are currently available 
for Django. 

**urls.py** it is a router that connects links (urls) and views (views). 

**wsgi.py** contains the necessary configuration for the **WSGI Protocol**. Next, to start 
the server, write the following command in the console: 
```
python manage.py runserver
```
As a result, the web server will be deployed and the client will be able to connect to it using 
the browser via the link **http://127.0.0.1:8000**. If the user needs to set other parameters, 
then you need to modify the command: 
```
python manage.py runserver 10.0.2.8:1234
```
There is almost no need for the user to modify the configuration, which is why it is easy to 
configure and use this framework. Since we use the **ASGI Protocol** to process network asynchronous 
code, we need to create **asgi.py** and **routing.py**. File **asgi.py** contains the configuration 
for the **ASGI Protocol**.

Before proceeding to the next step, the developers recommend that you first configure setting.py
 to check for errors in the ASGI Protocol. To do this, you need to setting.py replace the expression 
```
WSGI_APPLICATION = 'HackTool.wsgi.application' 
```
with
``` 
ASGI_APPLICATION = 'HackTool.routing.application' 
```
and add the expression ‘channels’ to the list of installed applications.

After successfully creating the project settings and **settings.py**, you need to create applications 
that combine logically related tasks. This project has 4 applications named 
command_line, mac_change, scan, and spoofing. To create an application, you must enter this 
line in the command line: 
```
python manage.py startapp "command_line"
```
Django will automatically generate all the necessary directory structure 
and the code inside the files, the developer needs only to configure the logic of the program.

After creating the application, for convenience and to increase the speed of the program, 
you must manually add the file urls.py, which will contain links to views. In the file 
views.py you must specify what will be performed by the application when trying to access 
the link to localhost\command_line.HTML.

As soon as the server receives a request from http://localhost:8000/command_line, it will 
execute the code located at the consumer. At this stage, the developer writes the logic 
that will be executed by the server. First, you need to register listening for connection 
events, receiving packets, and disconnecting – connect, disconnect, and receive, respectively. 
When a client visits a website, the client sends a request to the server. The "connect" event is 
called, where you need to accept the connection using the "accept"method. If the server executes 
the code with an error or the client reloads the page, the “disconnect”method is called. In this 
method, you need to implement the output of the connection closing code and the "pass" method, 
which suppresses thrown exceptions. Events must be silenced so that the server continues to work 
and does not stop during code execution.

### Web app functionality:
1. Changing the MAC address;
2. Console emulation;
3. Spoofing IP addresses in the ARP table;
4. DNS spoofing addresses;
5. Code injection on the user's page;
6. Spoofing files when trying to download;
7. Network scan;
8. Advanced IP address scanning;
9. SQL-injection;
10. Embedding XSS code on the server;
11. MD5 hashing and MD5 hash hacking;
12. Hacking user accounts by brute force.

As a result, 2 of the most common and dangerous types of malicious software were successfully 
developed: a remote access program, as well as software that can register user's keystrokes. 
It should be noted that this software is not detected by many modern antivirus programs, 
bacause they are written manually and are not included in the database of many antivirus applications.

### TODO
Integration with Metasplitable and NMap.