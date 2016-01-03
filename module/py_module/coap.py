from scapy.layers.inet import *

from udp_scapy import *
from threading import *
# 0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |Ver| T |  TKL  |      Code     |          Message ID           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Token (if any, TKL bytes) ...
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Options (if any) ...
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |1 1 1 1 1 1 1 1|    Payload (if any) ...
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# class CoAPtTokenLengthField(BitFieldLenField)
class CoAP(Packet):
    name = "CoAP"
    fields_desc = [BitField("version", 0, 2),
                   BitField("type", None, 2),
                   BitFieldLenField("tklen", None, 4, count_of="token"),
                   ByteEnumField("code", None, {0: "empty", 1: "request", 32: "response"}),
                   ShortField("id", None),
                   FieldListField("token", None, ByteField("token_entry", 0), count_from=lambda pkt: pkt.tklen),
                   ]


bind_layers(UDPPacket, CoAP)


class CoAPCore(object):
    def __init__(self):
        self.port_set = set()
        self.token_set = set()
        self.set_lock = Lock()
        self.map_lock = Lock()
        self.token_map = {}
        self.DEBUG_FAKE_DROP = True
    def send(self, dip, sp, dp):
        if not self.token_map:
            msg = ""
            msg += raw_input("msg: ")
            msg = str(0xFF) + msg
            identifier = random.getrandbits(16)  # random identifier
            local_token = random.getrandbits(8)  # token with size 1
            self.token_set.add(local_token)
            udp_field = UDPPacket(sport=sp, dport=dp, len=None, chksum=None)
            coap_field = CoAP(version=0, type=0, code = 1, id=identifier, token=local_token)
            coap_field.add_payload(msg)
            udp_field.add_payload(coap_field)
            udp_field.show()
            self.map_lock.acquire()
            self.token_map[local_token] = [udp_field, dip]
            self.map_lock.release()
            send_payload_to_ip(udp_field, dip, 17)
        else:
            self.check()

    def listen(self, port):
        self.port_set.add(port)

    def check(self):
        print("checking token map...")
        self.map_lock.acquire()
        for token in self.token_map:
            send_payload_to_ip(self.token_map[token][0], self.token_map[token][1], 17)
        self.map_lock.release()

core = CoAPCore()

# easy debug:
core.port_set.add(8888)


# #
# public functions
# MUST IMPLEMENT

def Protocol_Processor(meta_pkt):
    global core
    gpacket = GPacket(meta_pkt)
    udp_field = gpacket.packet.payload.payload
    coap_field = udp_field.payload
    udp_field.show()
    if coap_field.type == 0:
        print("recieved ", coap_field.token)
        if core.DEBUG_FAKE_DROP == True:
            core.DEBUG_FAKE_DROP = False
            return
        reply_coap = CoAP(version=coap_field.version, type=2, code=32, id=coap_field.id, token=coap_field.token)
        reply_udp = UDPPacket(sport=udp_field.dport, dport=udp_field.sport, len=None, chksum=None)
        reply_udp.add_payload(reply_coap)
        send_payload_to_ip(reply_udp, gpacket.packet.payload.src, 17)
    if coap_field.type == 1:
        print("ACK received")
        core.map_lock.acquire()
        core.token_map.pop(coap_field.token, None)
        core.map_lock.release()

def Command_Line(str):
    global core
    if core == None:
        core = CoAPCore()
    command_string = str.split(" ")
    if len(command_string) != 3:
        print('Command Error! "coap -l [port]" "nc [IP][port]"')
    elif command_string[1] == "-l":
        port_listen = int(command_string[2])
        core.listen(port_listen)
        print("listen to port", command_string[2], "...")
    else:
        dip_hl = command_string[1]
        dport = int(command_string[2])
        sport = 7777
        core.send(dip_hl, sport, dport)


def Config():
    print("[Config]")
    config = module_config(name="coap", protocol=17, command_string="coap", short_help="coap function",
                           usage="nc -l [port] nc [IP][port]",
                           long_help="sending and listening to udp packet")
    return config
