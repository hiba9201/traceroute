import struct
import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))

import logic.utils as u
import logic.traceroute as tr


class TestUtils(unittest.TestCase):
    def test_unpack(self):
        unpacked = u.Utils.unpack_packet_header(struct.pack('!BBHHH', 8, 0,
                                                            12, 12, 12))
        self.assertEqual((8, 0, 12, 12, 12), unpacked)

    def test_checksum(self):
        checksum = u.Utils.get_checksum(struct.pack('!BBHHHQQQQQL',
                                                    8, 0, 0, 12, 12,
                                                    2, 0, 0, 0, 0, 0))
        self.assertEqual(63461, checksum)

    def test_get_output(self):
        self.assertEqual('*       ', u.Utils.get_output('*'))

    def test_create_packet(self):
        packet = u.Utils.create_packet(12)
        header = struct.pack('!BBHHHQQQQQL', 8, 0, 0, tr.Traceroute.ID, 12, 2,
                             0, 0, 0, 0, 0)
        expected_packet = struct.pack('!BBHHHQQQQQL', 8, 0,
                                      u.Utils.get_checksum(header),
                                      tr.Traceroute.ID, 12, 2, 0, 0, 0, 0, 0)
        self.assertEqual(expected_packet, packet)

    def test_get_output_code_success(self):
        sequence = [12, 13, 14]
        packet = (0, 0, 12, tr.Traceroute.ID, 12)
        self.assertEqual(u.OutputType.SUCCESS.value,
                         u.Utils.get_output_code(sequence, packet, packet))

        packet = (11, 0, 12, 12, 12)
        data = struct.pack('!QQQQQQBBHHH', 11, 0, 12, 12, 12, 12,
                           8, 0, 12, tr.Traceroute.ID, 12)
        self.assertEqual(u.OutputType.SUCCESS.value,
                         u.Utils.get_output_code(sequence, packet, data))

    def test_get_output_code_error(self):
        sequence = [12, 13, 14]
        packet = (0, 0, 12, 12, 12)
        self.assertEqual(u.OutputType.ERROR.value,
                         u.Utils.get_output_code(sequence, packet, packet))

    def test_get_output_code_with_exclamation_mark(self):
        sequence = [12, 13, 14]
        packet = (3, 0, 12, 12, 12)
        self.assertEqual(u.OutputType.NET.value,
                         u.Utils.get_output_code(sequence, packet, packet))
        packet = (3, 1, 12, 12, 12)
        self.assertEqual(u.OutputType.HOST.value,
                         u.Utils.get_output_code(sequence, packet, packet))
        packet = (3, 9, 12, 12, 12)
        self.assertEqual(u.OutputType.PROHIB.value,
                         u.Utils.get_output_code(sequence, packet, packet))
        packet = (3, 3, 12, 12, 12)
        self.assertEqual('!3',
                         u.Utils.get_output_code(sequence, packet, packet))

    def test_proccess_output_code(self):
        code = u.OutputType.SUCCESS.value
        self.assertEqual('1.222ms', u.Utils.process_output_code(code, 1.2222))
        code = u.OutputType.NET.value
        self.assertEqual('1.222ms !N',
                         u.Utils.process_output_code(code, 1.2222))
        code = '*'
        self.assertEqual('*', u.Utils.process_output_code(code, 1.2222))
