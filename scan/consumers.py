from channels.generic.websocket import WebsocketConsumer
from json import dumps, loads
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from requests import Session
from re import findall
from bs4 import BeautifulSoup
from urllib import parse
from urllib3.exceptions import NewConnectionError
from os import getcwd
from  hashlib import md5


class NetworkScan(WebsocketConsumer):
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        #await self.close()
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)

        if "range" in text_data and len(text_data_json["range"])>0:
            self.print_result(self.scan(text_data_json["range"]))
        else:
            self.send(text_data=dumps({
                'arp_spoof_error': "Please, fill all fields correctly"
            }))

    def scan(self, ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = []

        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)

        return clients_list

    def print_result(self, results_list):
        self.send(text_data=dumps({
            'net_scan_result': "IP\t\t\tMAC Address\n------------------------------------------"
        }))

        for client in results_list:
            self.send(text_data=dumps({
                'net_scan_result': client["ip"] + "\t\t" + client["mac"]
            }))

# TODO NMAP SCANNER
class AdvancedNetworkScan(WebsocketConsumer):
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        #await self.close()
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)

class WebApplicationScan(WebsocketConsumer):

    session = Session()

    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)
        if len(text_data_json["targetUrl"])>0 and len(text_data_json["inputUsername"])>0 and len(text_data_json["username"])>0 \
                and len(text_data_json["inputPassword"]) > 0 and len(text_data_json["password"])>0 \
                and len(text_data_json["inputSubmit"])>0 and len(text_data_json["submitType"]) > 0:
            target_url = text_data_json["targetUrl"]
            input_username = text_data_json["inputUsername"]
            username = text_data_json["username"]
            input_password = text_data_json["inputPassword"]
            password = text_data_json["password"]
            input_submit = text_data_json["inputSubmit"]
            submit_type = text_data_json["submitType"]
            data_dict = {input_username: username,
                         input_password: password,
                         input_submit: submit_type}
            self.session.post(target_url, data = data_dict)
            self.http_request_check(target_url)
            self.server_fingerprinting(target_url)
            self.insecure_headers(target_url)
            self.clickjacking(target_url)
            self.insecure_coockies(target_url)
            self.cookies_fixation(data_dict, target_url)
        elif len(text_data_json["targetUrl"])>0:
            target_url = text_data_json["targetUrl"]
            self.http_request_check(target_url)
            self.server_fingerprinting(target_url)
            self.insecure_headers(target_url)
            self.clickjacking(target_url)
            self.insecure_coockies(target_url)
        else:
            self.send(text_data=dumps({
                'error': "Please, fill all fields correctly"
            }))

    def http_request_check(self, target_url):
        print("hello")
        verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE',
                 'TEST']
        # session = Session()
        for verb in verbs:
            req = self.session.request(verb, target_url)
            self.send(text_data=dumps({
                'result': str(verb) + " " + str(req.status_code) + " " + str(req.reason)
            }))
            print(verb, req.status_code, req.reason)
            if verb == "TRACE" and req.status_code == 200:
                self.send(text_data=dumps({
                    'error': 'Possible Cross Site Tracing vulnerability found'
                }))
                print('Possible Cross Site Tracing vulnerability found')

    def server_fingerprinting(self, target_url):
        session = Session()
        req = session.get(target_url)
        headers = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country-Code']
        for header in headers:
            try:
                # print(req.headers)
                result = req.headers[header]
                self.send(text_data=dumps({
                    'result': str(header) + " : " + str(result)
                }))
                print('%s: %s' % (header, result))
            except Exception as error:
                self.send(text_data=dumps({
                    'result': str(header) + ": Not found"
                }))
                print('%s: Not found' % header)

    def insecure_headers(self, target_url):
        # urls = open("urls.txt", "r")
        # for url in urls:
        #     url = url.strip()
        #     req = requests.get(url)
        #     print(url, 'report:')
        session = Session()
        req = session.get(target_url)
        try:
            xssprotect = req.headers['X-XSS-Protection']
            if xssprotect != '1; mode=block':
                self.send(text_data=dumps({
                    'error': 'X-XSS-Protection not set properly, XSS may be possible: '+ str(xssprotect)
                }))
                print('X-XSS-Protection not set properly, XSS may be possible: ', xssprotect)
        except:
            self.send(text_data=dumps({
                    'error': 'X-XSS-Protection not set, XSS may be possible'
                }))
            print('X-XSS-Protection not set, XSS may be possible')
        try:
            contenttype = req.headers['X-Content-Type-Options']
            if contenttype != 'nosniff':
                self.send(text_data=dumps({
                    'error': 'X-Content-Type-Options not set properly:' + str(contenttype)
                }))
                print('X-Content-Type-Options not set properly:', contenttype)
        except:
            self.send(text_data=dumps({
                    'error': 'X-Content-Type-Options not set. MIME attacks possible'
                }))
            print('X-Content-Type-Options not set. MIME attacks possible')
        try:
            hsts = req.headers['Strict-Transport-Security']
        except:
            self.send(text_data=dumps({
                    'error': 'HSTS header not set, MITM attacks may be possible'
                }))
            print('HSTS header not set, MITM attacks may be possible')
        try:
            csp = req.headers['Content-Security-Policy']
            self.send(text_data=dumps({
                'result': 'Content-Security-Policy set:' + str(csp)
            }))
            print('Content-Security-Policy set:', csp)
        except:
            self.send(text_data=dumps({
                    'error': 'Content-Security-Policy missing'
                }))
            print('Content-Security-Policy missing')

    def clickjacking(self, target_url):
        URL = target_url
        session = Session()
        req = session.get(URL, verify=False)
        try:
            xframe = req.headers['x-frame-options']
            self.send(text_data=dumps({
                'result': 'X-FRAME-OPTIONS:' + str(xframe) + 'present, clickjacking not likely possible'
            }))
            print('X-FRAME-OPTIONS:', xframe, 'present, clickjacking not likely possible')
        except:
            self.send(text_data=dumps({
                'error': 'X-FRAME-OPTIONS missing. Clickjacking is highly possible!'
            }))
            print('X-FRAME-OPTIONS missing. Clickjacking is highly possible!')

    def insecure_coockies(self, target_url):
        session = Session()
        # req = session.post("http://10.0.2.6/dvwa/login.php", data = data_dict)
        req = session.get(target_url)
        # print(req.headers)
        try:
            for cookie in req.cookies:
                self.send(text_data=dumps({
                    'result': 'Name:' + str(cookie.name)
                }))
                self.send(text_data=dumps({
                    'result': 'Value:' + str(cookie.value)
                }))
                print('Name:', cookie.name)
                print('Value:', cookie.value)
                if not cookie.secure:
                    cookie.secure = 'False'
                    self.send(text_data=dumps({
                        'error': 'Cookies can be sniffed over the wire'
                    }))
                    print('Cookies can be sniffed over the wire')
                self.send(text_data=dumps({
                    'result': 'Secure:' + str(cookie.secure)
                }))
                print('Secure:', cookie.secure)
                if 'httponly' in cookie._rest.keys():
                    cookie.httponly = 'True'
                    self.send(text_data=dumps({
                        'error': 'JavaScript can access cookies'
                    }))
                    print('JavaScript can access cookies')
                else:
                    cookie.httponly = 'False'
                print('HTTPOnly:', cookie.httponly)
                if cookie.domain_initial_dot:
                    cookie.domain_initial_dot = 'True'
                self.send(text_data=dumps({
                    'error': 'Loosly defined domain:' + str(cookie.domain_initial_dot)
                }))
                print('Loosly defined domain:', cookie.domain_initial_dot, '\n')
        except Exception:
            self.send(text_data=dumps({
                'result': "There is no cookies"
            }))
            print("There is no cookies")

    def cookies_fixation(self, data_dict, target_url):
        session = Session()
        url = target_url
        req = session.get(url)
        if req.cookies:
            # cookies = session.cookies.get_dict()
            print(session.cookies.get_dict())
            print('Initial cookie state:', req.cookies)
            cookie_req = session.post(url, data=data_dict, cookies=req.cookies)
            print('Authenticated cookie state:', cookie_req.cookies)
            if req.cookies == cookie_req.cookies:
                print('Session fixation vulnerability identified')
            else:
                print('There is no cookies fixation')
        session.close()

class XssScan(WebsocketConsumer):

    session = Session()
    target_links = []
    target_url = ''
    links_to_ignore = []

    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        #await self.close()
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)
        if len(text_data_json["targetUrl"])>0 and len(text_data_json["inputUsername"])>0 and len(text_data_json["username"])>0 \
                and len(text_data_json["inputPassword"]) > 0 and len(text_data_json["password"])>0 \
                and len(text_data_json["inputSubmit"])>0 and len(text_data_json["submitType"]) > 0:
            target_url = text_data_json["targetUrl"]
            input_username = text_data_json["inputUsername"]
            username = text_data_json["username"]
            input_password = text_data_json["inputPassword"]
            password = text_data_json["password"]
            input_submit = text_data_json["inputSubmit"]
            submit_type = text_data_json["submitType"]
            data_dict = {input_username: username,
                         input_password: password,
                         input_submit: submit_type}
            self.links_to_ignore = ["http://10.0.2.6/dvwa/logout.php"]
            self.session.post(target_url, data = data_dict)
        elif len(text_data_json["targetUrl"])>0:
            self.target_url = text_data_json["targetUrl"]
            self.links_to_ignore = ["http://10.0.2.6/dvwa/logout.php"]
            self.crawl()
            self.run_scanner()
        else:
            self.send(text_data=dumps({
                'error': "Please, fill all fields correctly"
            }))

    def extract_links_from(self, url):
        try:
            response = self.session.get(url)
            return findall('(?:href=")(.*?)"', response.content.decode("cp866"))
        except (OSError, NewConnectionError, ConnectionError) as e:
            self.send(text_data=dumps({
                'error': "The host is unreachable"
            }))
            return []

    def crawl(self, url=None):
        if url is None:
            url = self.target_url
        href_links = self.extract_links_from(url)
        for link in href_links:
            link = parse.urljoin(url, link)

            if link[-1] == "/":
                link = link[:-1]

            if "{{data.url}}" in link or "::javascript" in link:
                continue

            if "#" in link:
                link = link.split("#")[0]

            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)
                print(link)
                self.crawl(link)

    def extract_forms(self, url):
        try:
            response = self.session.get(url)
            parse_html = BeautifulSoup(response.content, "html.parser")
            return parse_html.findAll("form")
        except ConnectionError:
            self.send(text_data=dumps({
                'error': "Please, fill all fields correctly"
            }))

    def submit_form(self, form, value, url):
        try:
            action = form.get("action")
            method = form.get("method")
            post_url = parse.urljoin(url, action)

            inputs_list = form.findAll("input")
            post_data = {}
            for __input in inputs_list:
                input_name = __input.get("name")
                input_type = __input.get("type")
                input_value = __input.get("value")
                if input_type == "text":
                    input_value = value

                post_data[input_name] = input_value

                if method == "post":
                    return self.session.post(post_url, data=post_data)
                return self.session.get(post_url, params=post_data)
        except ConnectionError:
            self.send(text_data=dumps({
                'error': "Please, fill all fields correctly"
            }))

    def run_scanner(self):
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print("[+] Testing form in " + link)
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    self.send(text_data=dumps({
                        'result': "\n\n################XSS is Discovered################\n in " + link + " in the following form "
                    }))
                    print("\n\n################XSS is Discovered################\n in "
                          + link + " in the following form ")
                    print(form)
            if "=" in link:
                print("[+] Testing " + link)
                is_vulnerable_to_xss = self.test_xss_in_link(link)
                if is_vulnerable_to_xss:
                    self.send(text_data=dumps({
                        'result': "\n\n################XSS is Discovered################\n in " + link
                    }))
                    print("\n\n################XSS is Discovered################\n in "
                          + link)

    def test_xss_in_link(self, url):
        try:
            xss_test_script = "<sCript>alert('test')</scriPt>"
            url = url.replace("=", "=" + xss_test_script)
            response = self.session.get(url)
            return xss_test_script in response.content.decode()
        except ConnectionError:
            self.send(text_data=dumps({
                'error': "Please, fill all fields correctly"
            }))


    def test_xss_in_form(self, form, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        response = self.submit_form(form, xss_test_script, url)
        if response is not None:
            return xss_test_script in response.content.decode()
        else:
            return False

# TODO SQL INJECTION
class SQLInjectionScan(WebsocketConsumer):
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        #await self.close()
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)

class PageBruteforce(WebsocketConsumer):

    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)
        if len(text_data_json["targetUrl"]) > 0 and len(text_data_json["userList"]) > 0 \
                and len(text_data_json["passwordList"]) > 0 and len(text_data_json["failStr"]) > 0:
            url = text_data_json["targetUrl"]
            print(getcwd())
            path = str(getcwd()) + '/templates/txt/'
            userlist = open(path + str(text_data_json["userList"]),'r')
            passwordlist = open(path + str(text_data_json["passwordList"]),'r')
            FailStr = text_data_json["failStr"]
            session = Session()
            headers = {}

            self.brute(userlist, passwordlist, FailStr, url, session)
        else:
            self.send(text_data=dumps({
                'error': "The host is unreachable"
            }))


    def brute(self, userlist, passwordlist, FailStr, url, session):
        foundusers = []
        try:
            for user in userlist:
                user = user.split("\n")
                for password in passwordlist:
                    password = password.split("\n")
                    data = {'username': user[0], 'password': password[0],
                            'Login': 'submit'}
                    response = session.post(url, data=data)
                    if (FailStr not in response.text):
                        foundusers.append(user[0] + ":" + password[0])
            if len(foundusers) > 0:
                self.send(text_data=dumps({
                    'result': "Found User and Password combinations:"
                }))
                print("Found User and Password combinations:\n")
                for name in foundusers:
                    print(name)
                    self.send(text_data=dumps({
                        'result': str(name)
                    }))
            else:
                print("No users found\n")
        except (OSError, NewConnectionError, ConnectionError) as e:
            self.send(text_data=dumps({
                'error': "The host is unreachable"
            }))

class MD5Encrypt(WebsocketConsumer):
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)
        if len(text_data_json["word"]) > 0:
            self.send(text_data=dumps({
                'result': str(md5(text_data_json["word"].encode()).hexdigest())
            }))
        else:
            self.send(text_data=dumps({
                'error': "The host is unreachable"
            }))

class MD5Decrypt(WebsocketConsumer):
    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)
        if len(text_data_json["md5Hash"]) > 0 and len(text_data_json["dictionary"]) > 0:
            target = text_data_json["md5Hash"]
            dictionary = text_data_json["dictionary"]
            self.md5decrypt(target, dictionary)
        else:
            self.send(text_data=dumps({
                'error': "The host is unreachable"
            }))

    def md5decrypt(self, target, dictionary):
        path = str(getcwd()) + '/templates/txt/'
        with open(path + dictionary, 'r') as fileobj:
            for line in fileobj:
                line = line.strip("\n").encode()
                print(target, line)
                try:
                    if md5(line).hexdigest() == target:
                        print("Hash was successfully cracked %s.\nThe value is %s" % (target, line))
                        self.send(text_data=dumps({
                            'result': str("Hash was successfully cracked %s:\nThe value is %s" % (target, line.decode()))
                        }))
                        return ""
                except UnicodeDecodeError:
                    pass
        print("Failed to crack the file.")
