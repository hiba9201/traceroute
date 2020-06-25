import struct
import time
import unittest
import unittest.mock as mock
import functools
import sys
import os
import socket

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))

import logic.traceroute as tr
import logic.utils as u


class Arguments:
    def __init__(self):
        self.start = 1
        self.packets = 3
        self.wait = 1
        self.hops = 64
        self.pause = 1
        self.host = '127.0.0.1'
        self.is_ip = False


def count_calls(func):
    count = []

    @functools.wraps(func)
    def return_function(*args, **kwargs):
        count.append(0)
        if len(count) < 3:
            return func(*args, **kwargs)
        return u.OutputType.SUCCESS.value

    return return_function


@count_calls
def ignore(*args):
    return u.OutputType.ERROR.value


class TestTraceroute(unittest.TestCase):
    @mock.patch('logic.network_utils.NetworkUtils.create_socket')
    @mock.patch('logic.utils.Utils.get_output_code', side_effect=ignore)
    @mock.patch('logic.traceroute.socket')
    def test_repeat_recv_on_error(self, Socket, output, create):
        sock = Socket()
        sock.recvfrom.return_value = [struct.pack('!qqLBBHHH', 1, 1, 1, 0, 0,
                                                  1, 32222, 1),
                                      ['0.0.0.0', 0]]
        tracert = tr.Traceroute(Arguments())
        tracert.sock = sock

        tracert.trace_one_packet(struct.pack('!BBHHH', 8, 0, 1, 1, 1), 'name')
        self.assertEqual(sock.recvfrom.call_count, 3)

    @mock.patch('logic.network_utils.NetworkUtils.create_socket')
    @mock.patch('logic.traceroute.socket')
    def test_on_timeout(self, Socket, create):
        sock = Socket()
        sock.recvfrom.return_value = [struct.pack('!qqLBBHHH', 1, 1, 1, 0, 0,
                                                  1, 32222, 1),
                                      ['127.0.0.1', 0]]
        sock.recvfrom.side_effect = socket.timeout
        tr.socket.timeout = socket.timeout

        tracert = tr.Traceroute(Arguments())
        tracert.sock = sock
        name, _ = tracert.trace_one_packet(struct.pack('!BBHHH',
                                                       8, 0, 1, 1, 1), None)
        self.assertEqual(name, 'Packet receiving timeout')
        self.assertEqual(tracert.current_line, [u.Utils.get_output('*')])

    @mock.patch('logic.network_utils.NetworkUtils.create_socket')
    @mock.patch('logic.utils.Utils.get_output_code',
                return_value=u.OutputType.SUCCESS.value)
    @mock.patch('logic.traceroute.socket')
    def test_on_success(self, Socket, output, create):
        sock = Socket()
        sock.recvfrom.return_value = [struct.pack('!qqLBBHHH', 1, 1, 1, 0, 0,
                                                  1, 32222, 1),
                                      ['127.0.0.1', 0]]
        tr.socket.gethostbyaddr.side_effect = socket.gethostbyaddr
        tracert = tr.Traceroute(Arguments())
        tracert.sock = sock
        name, addr = tracert.trace_one_packet(struct.pack('!BBHHH',
                                                          8, 0, 1, 1, 1), None)
        self.assertEqual(name, f'localhost ({addr})')
        self.assertEqual(addr, '127.0.0.1')

    @mock.patch('logic.network_utils.NetworkUtils.create_socket')
    @mock.patch('logic.utils.Utils.get_output_code',
                return_value=u.OutputType.SUCCESS.value)
    @mock.patch('logic.traceroute.socket')
    def test_on_success_but_no_host(self, Socket, output, create):
        sock = Socket()
        sock.recvfrom.return_value = [struct.pack('!qqLBBHHH', 1, 1, 1, 0, 0,
                                                  1, 32222, 1),
                                      ['127.0.0.1', 0]]
        tr.socket.error = socket.error
        tr.socket.gethostbyaddr.side_effect = socket.error
        tracert = tr.Traceroute(Arguments())
        tracert.sock = sock
        name, addr = tracert.trace_one_packet(struct.pack('!BBHHH',
                                                          8, 0, 1, 1, 1), None)
        self.assertEqual(name, f'127.0.0.1 ({addr})')
        self.assertEqual(addr, '127.0.0.1')
