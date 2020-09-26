from channels.generic.websocket import WebsocketConsumer
from json import loads, dumps
from subprocess import check_output, STDOUT

class CommandLine(WebsocketConsumer):

    def connect(self):
         self.accept()

    def disconnect(self, close_code):
        print("disconnect", close_code)
        pass

    def receive(self, text_data):
        text_data_json = loads(text_data)
        print(text_data)
        if "cmd_text" in text_data and len(text_data_json['cmd_text'])>0:
            self.send(text_data=dumps({
                'command_line_result': check_output(text_data_json['cmd_text'] + '; exit 0', stderr=STDOUT, shell=True, universal_newlines=True)
            }))
        else:
            self.send(text_data=dumps({
                'command_line_error': "Please, fill all fields correctly"
            }))

