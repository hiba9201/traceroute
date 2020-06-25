import socket
import time
import struct
import random

import logic.network_utils as nu
import logic.utils as u


class Traceroute:
    ID = random.randint(0, 65535)

    def __init__(self, args):
        self.args = args
        self.port = random.choice(range(33434, 33535))
        self.ttl = self.args.start
        self.sequence = list(range(1, self.args.packets + 1))
        self.sock = nu.NetworkUtils.create_socket('', self.port,
                                                  self.args.wait)
        self.address = socket.gethostbyname(self.args.host)
        self.output = []
        self.current_line = []

    def trace(self):
        """Method traces the route to the chosen destination"""
        self.output.append(u.Utils.create_start_tracing(self.args.host,
                                                        self.address,
                                                        self.args.hops,
                                                        self.args.packets))

        while self.ttl < self.args.hops:
            name = None
            self.current_line.append(str(self.ttl).rjust(len(
                str(self.args.hops))))

            for i in range(self.args.packets):
                time.sleep(self.args.pause)
                packet = u.Utils.create_packet(self.sequence[i])
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL,
                                     struct.pack('I', self.ttl))
                name, received_addr = self.trace_one_packet(packet, name)

            self.sequence = list(map(lambda num: num + self.args.packets,
                                 self.sequence))

            self.current_line.append(name)
            self.output.append(' '.join(self.current_line))
            self.current_line = []

            if received_addr == self.address:
                self.output.append('Tracing complete!')
                break
            self.ttl += 1

        return self.output

    def trace_one_packet(self, packet, name):
        """Main tracert algorithm"""
        start_time = time.perf_counter()
        self.sock.sendto(packet, (self.address, self.port))
        output_code = u.OutputType.ERROR.value

        while output_code == u.OutputType.ERROR.value:
            try:
                data, received_addr = self.sock.recvfrom(1024)
                dtime = (time.perf_counter() - start_time) * 1000
                received_addr = received_addr[0]
                header = u.Utils.unpack_packet_header(data[20:28])
                output_code = u.Utils.get_output_code(self.sequence, header,
                                                      data)

            except socket.timeout:
                received_addr = None
                output_code = '*'

            if received_addr:
                output_code = u.Utils.process_output_code(output_code, dtime)

            if output_code != u.OutputType.ERROR.value:
                self.current_line.append(u.Utils.get_output(output_code))

            if output_code == '*':
                if name is None:
                    name = 'Packet receiving timeout'
            elif (received_addr is not None and
                  output_code != u.OutputType.ERROR.value):
                try:
                    received_host = socket.gethostbyaddr(received_addr
                                                         )[0] + ' '
                except socket.error:
                    received_host = f'{received_addr} '
                if self.args.is_ip:
                    received_host = ''
                name = f'{received_host}({received_addr})'

        return name, received_addr
