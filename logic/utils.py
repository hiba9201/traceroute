import struct
import enum
import logic.traceroute as tr


class OutputType(enum.Enum):
    NET = '!N'
    HOST = '!H'
    PROHIB = '!X'
    SUCCESS = 'OK'
    ERROR = 'ERROR'


class Utils:
    @staticmethod
    def create_start_tracing(host, addr, max_ttl, packets):
        return (f'Tracing route to {host} ({addr}). ' +
                f'Max hops: {max_ttl}. Packets per ttl: ' +
                f'{packets}')

    @staticmethod
    def unpack_packet_header(header):
        return struct.unpack('!BBHHH', header)

    @staticmethod
    def get_checksum(packet):
        """Counts checksum for icmp-packet"""
        unpacked = struct.unpack('!LLLLLLLLLLLLL', packet)
        res = sum(unpacked)
        res += (res >> 16)

        return ~res & 0xffff

    @staticmethod
    def get_output(output_code):
        """Prints one line of output for tracert"""
        return output_code.ljust(8)

    @staticmethod
    def create_packet(sequence_number):
        """
        Creates echo request icmp-packet with chosen sequence number and ID
        """
        icmp_header = struct.pack('!BBHHH', 8, 0, 0, tr.Traceroute.ID,
                                  sequence_number)
        icmp_data = struct.pack('!QQQQQL', 2, 0, 0, 0, 0, 0)
        checksum = Utils.get_checksum(icmp_header + icmp_data)
        icmp_header = struct.pack('!BBHHH', 8, 0, checksum, tr.Traceroute.ID,
                                  sequence_number)

        return icmp_header + icmp_data

    @staticmethod
    def get_output_code(sequence, pack_header, data):
        icmp_type = pack_header[0]

        if icmp_type == 3:
            code = pack_header[1]
            if code == 0:
                return OutputType.NET.value
            elif code == 1:
                return OutputType.HOST.value
            elif code in (9, 10, 13):
                return OutputType.PROHIB.value
            else:
                return f'!{code}'
        elif icmp_type == 11:
            inner_header = Utils.unpack_packet_header(data[48:56])
            if (inner_header[0] == 8 and
                    inner_header[3] == tr.Traceroute.ID and
                    inner_header[4] in sequence):
                return OutputType.SUCCESS.value
        elif icmp_type == 0:
            if (pack_header[3] == tr.Traceroute.ID and
                    pack_header[4] in sequence):
                return OutputType.SUCCESS.value

        return OutputType.ERROR.value

    @staticmethod
    def process_output_code(output_code, time):
        if output_code.startswith('!'):
            return f'{str(time)[:5]}ms {output_code}'

        if output_code == OutputType.SUCCESS.value:
            return f'{str(time)[:5]}ms'

        return output_code
