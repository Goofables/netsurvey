#!/usr/bin/env python
# @Name: scanner.py
# @Project: netsurvey/
# @Author: Goofables
# @Created: 5/18/23

import functools
import logging
import mmap
import socket
import struct
import time
from multiprocessing.pool import ThreadPool
from threading import Thread

from scapy.layers.inet import IP, TCP

PORT_MAP = (22, 80, 443, 139, 445, 3389, 3306, 25565)


class DB:
    def __init__(self):
        try:
            with open("scan_data.bin", "x") as f:
                pass
        except:
            pass
        self.f = open("scan_data.bin", "r+b")
        self.f.truncate(256 ** 4)
        self.map = mmap.mmap(self.f.fileno(), length=256 ** 4, access=mmap.ACCESS_WRITE)
        # self.map = self.f

    def read(self, n: int):
        self.map.seek(n, 0)
        return self.map.read(1)

    def write(self, n: int, data: int):
        self.map.seek(n, 0)
        return self.map.write(data.to_bytes(1, "little"))

    def or_bit(self, n: int, data: int):
        return self.write(n, int.from_bytes(self.read(n), "little") | data)

    def close(self):
        if self.f is not None:
            self.map.flush()
            self.map.close()
            self.f.close()
            self.f = None
            print("DB shut down")

    def __del__(self):
        self.close()


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def checksum(data):
    if len(data) % 2 == 1:
        data += b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += struct.unpack("!H", data[i:i + 2])[0]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return s & 0xffff


def tcp_syn(src: int, dst: int, src_port: int, dst_port: int):
    version = 4
    tcp_header_length = 5
    tos = 0
    total_length = 40
    identification = 1
    ip_flags = 0
    fragment_offset = 0
    ttl = 64
    protocol = 6
    ip_checksum = 0  # ????
    # src = 192 * 256 ** 3 + 168 * 256 ** 2 + 69 * 256 + 10  # static
    # dst = 256 ** 3 + 256 ** 2 + 256 + 1  # calc
    # src_port = s  # static
    # dst_port = 80  # semistatic
    seq = 0
    ack = 0
    header_len = 5
    tcp_flags = 2
    window = 8192
    tcp_checksum = 0
    urgent = 0
    tcp_with_pseudo_header = struct.pack(
        "!IIHHHHIIHHHH",
        src,
        dst,
        protocol, 20,
        src_port, dst_port,
        seq,
        ack,
        header_len << 12 | tcp_flags, window,
        tcp_checksum, urgent
    )
    # print(tcp_with_pseudo_header.hex())
    tcp_checksum = checksum(tcp_with_pseudo_header)
    ip_header = struct.pack(
        "!BBHHHBBHII",
        version << 4 | tcp_header_length, tos, total_length,
        identification, ip_flags << 13 | fragment_offset,
        ttl, protocol, ip_checksum,
        src,
        dst,
    )
    ip_checksum = checksum(ip_header)
    # print(f"TCP: {hex(tcp_checksum)} IP: {hex(ip_checksum)}")
    return struct.pack(
        "!BBHHHBBHIIHHIIHHHH",
        version << 4 | tcp_header_length, tos, total_length,
        identification, ip_flags << 13 | fragment_offset,
        ttl, protocol, ip_checksum,
        src,
        dst,
        src_port, dst_port,
        seq,
        ack,
        header_len << 12 | tcp_flags, window,
        tcp_checksum, urgent
    )


class RawTCPScanner:
    """
    Raw TCP port scanner. Starts a socket listening then floods packets from that socket.
    """

    """for reference: (RFC 761)
    Checksum
     +--------+--------+--------+--------+
     |           Source Address          |
     +--------+--------+--------+--------+
     |         Destination Address       |
     +--------+--------+--------+--------+
     |  zero  |  proto |    TCP Length   |
     +--------+--------+--------+--------+
    IP
      0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    TCP
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, *, src_addr: str, detected_port_callback: callable = None, _threads: int = 100):
        """
        :param network: Network to scan
        :param detected_port_callback: Callback function for when a port is detected
        """
        self.callback: callable = detected_port_callback

        self.logger = logging.getLogger("rawscan")
        self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)

        self.logger.debug("Initializing...")

        self.socket: socket.socket = None
        self.receiver_thread: Thread = None
        self.LISTEN_PORT: int = 0
        self.SRC_IP_INT = ip2int(src_addr)
        self.listening: bool = False

        self._init_socket()
        self.receiver_thread: Thread = Thread(target=self._listen_loop, args=())
        self.receiver_thread.start()

        self.sent_packets = 0
        self.start_time = time.time()

        # Threadpool because yes
        self.send_pool: ThreadPool = ThreadPool(_threads)

        self.logger.debug("Initialized!")

    def _init_socket(self) -> None:
        """
        Initialize the socket listener
        Broken out from init incase it ever needs to be reinitialized
        """
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_TCP)
        # Tell kernel to not do auto headers
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # 0 = random open port
        self.socket.bind(("0.0.0.0", 0))

        self.LISTEN_PORT: int = self.socket.getsockname()[1]
        self.logger.debug(f"Socket Listening on {self.LISTEN_PORT}")

        self.listening = True

    def _listen_loop(self) -> None:
        """
        This function sets up the listener to receive packets on the socket
        If the packet is within our scan range and is a Syn Ack packet then it is sent to the callback function
        If it's a new port/host combination we append it to our dictionary and call our callback function
        """
        reply_pool = ThreadPool(1)
        while self.listening:
            # Basically UDP. lol
            raw_bytes, address = self.socket.recvfrom(40)  # receive 40 bytes from * # 40 = tcp header

            # Confirm received packet is SYNACK
            if int(raw_bytes[33]) != (2 | 16): continue  # flags at 20 + 13; SYN=2 ACK=16

            # Gets the source port (at 20 + 0) from the raw bytes from the socket without scapy
            src_port = int.from_bytes(raw_bytes[20:22], byteorder='big')

            self.logger.debug(f"+{address[0]}: {address[1]} {src_port}")

            self.callback(address[0], src_port)

            # reset the connection so that target doesn't use up bandwidth trying to connect
            # reply_pool.apply_async(self._send_probe, (address[0], src_port, "R"))

    def _stop_listening(self) -> None:
        """
        Kills the listener thread
        """
        if not self.listening: return
        self.listening = False
        if self.receiver_thread is not None:
            self.receiver_thread.join()
            self.receiver_thread = None

    def _del_socket(self):
        """
        Close the socket
        """
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def _send_probe(self, address: str, port: int = 0, flags: str = "S") -> None:
        """
        Sends TCP packet with certain flag set from the listening socket
        Basically UDPs out a TCP packet
        :param address: destination ip address
        :param port: destination port
        """
        # self.logger.debug(f"Send to {address}:{port}")  # Very verbose
        self.sent_packets += 1
        self.socket.sendto(
            (IP(dst=address) / TCP(dport=port, flags=flags, sport=self.LISTEN_PORT)).build(),
            (address, 0)
        )

    def _send_syn(self, dst: int, port: int = 0) -> None:
        """
        Sends TCP packet with certain flag set from the listening socket
        Basically UDPs out a TCP packet
        :param address: destination ip address
        :param port: destination port
        """
        # self.logger.debug(f"Send to {address}:{port}")  # Very verbose
        self.sent_packets += 1
        self.socket.sendto(
            tcp_syn(src=self.SRC_IP_INT, dst=dst, src_port=self.LISTEN_PORT, dst_port=port),
            ("1.0.0.0", 0)
        )

    def send_probes(self, *, hosts: list[int], port: int, _threads: int = 20):
        """
        Gaelin's custom scanner with built-in callback function.

        Arguments:
            hosts: List of hosts to send probes to
            port: Port to send probes to
            sync_timeout: Timeout in seconds for synchronous data back. If 0 then assumed async
            _threads: Number of threads to send packets with
        """

        # the main scanning loop
        self.send_pool.imap_unordered(
            functools.partial(self._send_syn, port=port),
            hosts,
            chunksize=_threads
        )

    def __del__(self):
        # self.logger.info("Shutting down")
        self._stop_listening()
        self._del_socket()

    def shutdown(self):
        self.logger.info(f"Waiting for {len(self.send_pool._cache)} operations in send pool")
        self.send_pool.close()
        self.send_pool.join()
        total_time = time.time() - self.start_time
        self.logger.info("Shutting down scanning engine")
        self.logger.info(f"Time: {total_time:0.6f}s")
        self.logger.info(f"Sent: {self.sent_packets}")
        self.logger.info(f" PPS: {self.sent_packets / total_time:0.2f}")
        self.logger.info(f"MBPS: {self.sent_packets * 40 / (total_time * 10000000):0.10f} mbps")
        self.logger.info(f"   %: {self.sent_packets / total_time / 14_316_557 * 100:0.2f} %")
        self._stop_listening()
        self._del_socket()


database = DB()


def cb_write_port(addr, port):
    try:
        port_id = PORT_MAP.index(port)
    except ValueError:
        scanner.logger.debug(f"**{addr}: {port} invalid port")
        return
    print(f"Writing to {ip2int(addr)} val {port_id}")
    database.or_bit(ip2int(addr), port_id)


def ip_gen():
    pass


if __name__ == "__main__":
    logging.info("Starting")

    scanner = RawTCPScanner(src_addr="192.168.69.10", detected_port_callback=cb_write_port, _threads=20)
    scanner._send_syn(10 * 256 * 256 * 256 + 1, 80)
    scanner.shutdown()
    database.close()
