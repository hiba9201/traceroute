import socket


class NetworkUtils:
    @staticmethod
    def create_socket(host, port, timeout):
        """Creates socket for tracing"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        sock.bind((host, port))

        return sock
