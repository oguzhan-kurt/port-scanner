from array import array
import socket
import array
from optparse import OptionParser
from struct import pack, unpack
from fcntl import ioctl


class TCPScanner:

    def __init__(self,src_ip,dst_ip,dst_port):
        self._version            = 0x4   # Decimal -> 4
        self._hdrlen             = 0x5   # Decimal -> 5
        self._type_of_services   = 0x0   # Decimal -> 0
        self._total_lenght       = 0x3c  # Decimal -> 60
        self._identification     = 0xaaaa# Decimal -> 43690 (Random Value)
        self._ipflag             = 0x0   # Decimal -> 0
        self._fragment_offset    = 0x0   # Decimal -> 0
        self._ttl                = 0x40  # Decimal -> 64
        self._protocol           = 0x6   # Decimal -> 6
        self._header_checksum    = 0x0   # Decimal -> 0
        self._src_ip             = src_ip
        self._dst_ip             = dst_ip
        self._version_hdr_len    = (self._version << 4) + self._hdrlen
        self._f_fragmentoffset   = (self._ipflag << 13) +  self._fragment_offset

        #TCP Header
        self._src_port = 52374
        self._dst_port = dst_port
        self._seqnc_number        = 0x0
        self._ack_number          = 0x0
        self._data_offset         = (5 << 4)
        self._flag                = (0x0 << 5) + (0x0 << 4) + (0x0 << 3) + (0x0 << 2) + (0x1 << 1) + 0x0
        self._window_size         = 8143
        self._checksum            = 0x0
        self._urg_pointer         = 0x0

        

    def raw_ip_packet(self):
        packet = pack("!BBHHHBBH4s4s",
        self._version_hdr_len,
        self._type_of_services,
        self._total_lenght,
        self._identification,
        self._f_fragmentoffset,
        self._ttl,
        self._protocol,
        self._header_checksum,
        socket.inet_aton(self._src_ip),
        socket.inet_aton(self._dst_ip)
        )

        return packet

    def build_ip_packet(self):
        packet = pack("!BBHHHBBH4s4s",
            self._version_hdr_len,
            self._type_of_services,
            self._total_lenght,
            self._identification,
            self._f_fragmentoffset,
            self._ttl,
            self._protocol,
            self.calc_checksum(self.raw_ip_packet()),
            socket.inet_aton(self._src_ip),
            socket.inet_aton(self._dst_ip)
            )

        return packet

    def build_tcp_packet(self):
        packet = pack('!HHIIBBHHH',
            self._src_port,                # Source Port
            self._dst_port,                # Destination Port
            self._seqnc_number,            # Sequence Number
            self._ack_number,              # Acknoledgement Number
            self._data_offset,             # Data Offset
            self._flag,                    # Flags
            self._window_size,             # Window
            self._checksum,                # Checksum (initial value)
            self._urg_pointer              # Urgent pointer
        )
        pseudo_hdr = pack(
            '!4s4sHH',
            socket.inet_aton(self._src_ip),    # Source Address
            socket.inet_aton(self._dst_ip),    # Destination Address
            socket.IPPROTO_TCP,                 # Protocol ID
            len(packet)                         # TCP Length
        )
        checksum = self.chksum(pseudo_hdr + packet)
        packet = packet[:16] + pack('H', checksum) + packet[18:]

        return packet

    def full_packet(self):
        ip = self.build_ip_packet()
        tcp = self.build_tcp_packet()

        full = ip + tcp
        return full


    def chksum(self,packet):
        if len(packet) % 2 != 0:
            packet += b'\0'
            
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16    
        return (~res) & 0xffff

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i] 
            s = s + w
        # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

    def send_packet(self):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.sendto(self.full_packet(), (self._dst_ip, 0))
            data = s.recv(1024)
            return data


def get_ip_address(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(ioctl(
        s.fileno(),
        0x8915,     #SIOCGIFADDR
        pack('256s',interface[:15].encode("utf-8"))
    )[20:24])

def user_parameters():
    opt_options = OptionParser()
    opt_options.add_option("-t","--target"   ,dest="target_ip",help="Target IP")
    opt_options.add_option("-i","--interface",dest="interface",help="Interface\nDefault : 'eth0'")
    opt_options.add_option("-p","--port"     ,dest="port_"    ,help="Port Number")

    options_prmtr = opt_options.parse_args()[0]

    try:
        assert options_prmtr.target_ip   != None
    except AssertionError:
        print("\nPlease Target IP")

    return options_prmtr

def print_result(port,results):
    raw = unpack("!HHLLBBHHH",results[20:40])
    raw = hex(raw[5])
    if raw == "0x12":
        print(f"Port {port}    ==> Open ")
    elif raw == "0x14":
        print(f"Port {port}    ==> Closed or Filtered")
    
def print_result2(port,results):
    raw = unpack("!HHLLBBHHH",results[20:40])
    raw = hex(raw[5])
    if raw == "0x12":
        print(f"Port {port}    ==> Open ")

user_options = user_parameters()

target_ip   = user_options.target_ip
_intface   = user_options.interface
port_number = user_options.port_

print("\n")
print("Results ==>")
print("-------------\n")



if __name__ == "__main__":
    try:
        if _intface == None:
            ip = get_ip_address("eth0")
        else:
            ip = get_ip_address(_intface)
        
        if port_number == None:
            for i in range(1,65535):
                scan = TCPScanner(ip,target_ip,i)
                res = scan.send_packet()
                print_result2(i,res)

        elif port_number != None:
            _port1 = port_number.split("-")
            if len(_port1) == 2:
                for j in range(int(_port1[0]),int(_port1[1])+1):
                    scan1 = TCPScanner(ip,target_ip,j)
                    res1 = scan1.send_packet()
                    print_result(j,res1)
            else:
                    scan1 = TCPScanner(ip,target_ip,int(port_number))
                    res2 = scan1.send_packet()
                    print_result(port_number,res2)
    except TypeError:
        pass


