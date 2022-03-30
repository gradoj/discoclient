import socket
import requests
from struct import pack,unpack
from json import JSONDecodeError, load, loads, dump, dumps
from binascii import hexlify,unhexlify
import argparse
import logging
import json
import sys
import time
import mrpc

logging.basicConfig(level=logging.DEBUG)

PROTOCOL_VERSION = 2
"""GWMP Identifiers"""
PUSH_DATA = 0
PUSH_ACK = 1
PULL_DATA = 2
PULL_RESP = 3
PULL_ACK = 4
TX_ACK = 5

headers = {
    'User-Agent': 'INSERT_VALID_HEADER_HERE',
    'From': 'your@email.com'  # This is another valid field
}

def get_disco_id(hs_addr):
    url = "https://discomode.io/api/id?hs_addr="+str(hs_addr)

    try:
        data=requests.get(url=url, headers=headers)
        data=data.json()
        logging.info('data'+str(data))
    except JSONDecodeError:
        logging.exception("cannot get new disco_id")
        return

    logging.info('got disco id %s from %s', data['disco_id'], url)
    return data['disco_id']

def get_disco_packet(id,payload='30'):
    url = "https://discomode.io/api/disco?id="+str(id)+'&payload='+payload


    try:
        data=requests.get(url=url, headers=headers)
        data=data.json()
    except JSONDecodeError:
        logging.exception("disco_id not found")
        return

    logging.info('get disco packet %s from %s', data, url)
    return data

class GatewayMessage():
    """A Gateway Message.

    Messages sent between the LoRa gateway and the LoRa network
    server. The gateway message protocol operates over UDP and
    occupies the data area of a UDP packet. See Gateway to Server
    Interface Definition.

    Attributes:
        version (int): Protocol version - 0x01 or 0x02
        token (str): Arbitrary tracking value set by the gateway.
        id (int): Identifier - see GWMP Identifiers above.
        gatewayEUI (str): Gateway device identifier.
        payload (str): GWMP payload.
        remote (tuple): Gateway IP address and port.
        ptype (str): JSON protocol top-level object type.
    """

    def __init__(self, version=2, token=0, identifier=None,
                 gatewayEUI=None, txpk=None, remote=None,
                 ptype=None):
        """GatewayMessage initialisation method.

        Args:
            version (int): GWMP version.
            token (str): Message token.
            id: GWMP identifier.
            gatewayEUI: gateway device identifier.
            payload: GWMP payload.
            ptype (str): payload type
            remote: (host, port)

        Raises:
            TypeError: If payload argument is set to None.

        """
        self.version = version
        self.token = token
        self.id = identifier
        self.gatewayEUI = gatewayEUI
        self.payload = ''
        self.ptype = ptype
        self.remote = remote

        self.rxpk = None
        self.txpk = txpk
        self.stat = None

    @classmethod
    def decode(cls, data, remote):
        """Create a Message object from binary representation.

        Args:
            data (str): UDP packet data.
            remote (tuple): Gateway address and port.

        Returns:
            GatewayMessage object on success.

        """
        # Check length
        if len(data) < 4:
            raise DecodeError("Message too short.")
        # Decode header
        (version, token, identifer) = unpack('<BHB', data[:4])

        m = GatewayMessage(version=version, token=token, identifier=identifer)
        m.remote = remote
        # Test versions (1 or 2) and supported message types
        if ( m.version not in (1, 2) or 
             m.version == 1 and m.id not in (PUSH_DATA, PULL_DATA) or 
             m.version == 2 and m.id not in (PUSH_DATA, PULL_DATA, TX_ACK)
             ):
                pass
                #raise UnsupportedMethod()

        # Decode gateway EUI and payload
        if m.id == PUSH_DATA:
            logging.info('Received PUSH DATA from forwarder')
            if len(data) < 12:
                logging.error("PUSH_DATA message too short.")
            m.gatewayEUI = unpack('<Q', data[4:12])[0]
            m.payload = data[12:]
        elif m.id == PULL_DATA:
            logging.info('Received PULL_DATA from forwarder')
            if len(data) < 12:
                logging.error("PULL_DATA message too short.")
            m.gatewayEUI = unpack('<Q', data[4:12])[0]

        elif m.id == TX_ACK:
            m.payload = data[4:]

        # Decode PUSH_DATA payload
        if m.id == PUSH_DATA:
            try:
                jdata = loads(m.payload)
            except ValueError:
                logging.error("JSON payload decode error")
            m.ptype = list(jdata.keys())[0]
            # Rxpk payload - one or more.
        return m

    def encode(self):
        """Create a binary representation of message from Message object.

        Returns:
            String of packed data.

        """
        data = ''
        if self.id == PUSH_ACK:
            data = pack('<BHB', self.version, self.token, self.id)
        elif self.id == PULL_ACK:
            data = pack('<BHB', self.version, self.token, self.id)
        elif self.id == PULL_RESP:
            if self.version == 1:
                self.token = 0

            self.payload = json.dumps(self.txpk).encode('utf-8')
            data = pack('<BHB', self.version, self.token, self.id) + \
                    self.payload

        # Add this case receive join accept message from miner
        elif self.id == PULL_DATA:
            data = pack('<BHB', self.version, self.token, self.id) + unhexlify(self.gatewayEUI)

        return data


def sendPullResponse(remote, request, txpk, sock, gateway_eui=b'FFFFFFFFFFFFFFFF'):
    """"Send a PULL_RESP message to a gateway.

    The PULL_RESP message transports its payload, a JSON object,
    from the LoRa network server to the LoRa gateway. The length
    of a PULL_RESP message shall not exceed 1000 octets.

    Args:
        request (GatewayMessage): The decoded Pull Request
        txpk (Txpk): The txpk to be transported
    """
    remote = (remote[0], remote[1])

    m = GatewayMessage(version=request.version, token=request.token,
                identifier=PULL_RESP, gatewayEUI=gateway_eui,
                remote=remote, ptype='txpk', txpk=txpk)
    logging.info("Sending PULL_RESP message to %s:%d" % remote)

    sock.sendto(m.encode(), remote)
    data, address = sock.recvfrom(4096)

    logging.info('Received %s bytes from %s' % (len(data), address))

def sendPushAck(remote, request,sock):
    """"Send a PULL_ACK message to a gateway.

    """
    remote = (remote[0], remote[1])

    m = GatewayMessage(version=request.version, token=request.token,
                identifier=PUSH_ACK, gatewayEUI=b'FFFFFFFFFFFFFFFF',
                remote=remote, ptype=None)
    logging.info("Sending PULL_ACK message to %s:%d" % remote)

    sock.sendto(m.encode(), remote)

def disco_to_forwarder(id,payload,port=1681):
    ''' get disco packet from server using id and give to forwarder when polled on port

    '''
    # create socket for udp comms
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind the socket to the port
    server_address = ('', port)
    logging.info('Starting up on %s port %s' % server_address)
    sock.bind(server_address)

    # listen on port until we get a PULL_DATA from the forwarder and then give it disco packet
    while True:
        data, remote = sock.recvfrom(4096)
        logging.info('received %s bytes from %s' % (len(data), remote))

        # Decode the data from the gateway even though we don't really care        
        gm=GatewayMessage()
        message = gm.decode(data, remote)

        if message.id==PULL_DATA:
            txpk=get_disco_packet(id=id, payload=payload)
            sendPullResponse(remote,message,txpk,sock)
            break
        elif message.id==PUSH_DATA:
            sendPushAck(remote, message,sock)

def disco_session(packet_num,packet_delay,payload):
    # open json config file for config
    with open('disco.json') as json_file:
        config = load(json_file)

    # getting port to listen on and hs addr to associate with disco id
    listen_port = config['listen_port']
    hotspot_addr = config['hotspot_addr']
    id = config['disco_id']

    # get new disco id if one not found in config
    if id == None or id == '':
        logging.info('no discovery id found. getting new id')
        id = get_disco_id(hs_addr=hotspot_addr)
        config['disco_id'] = id

        # save back to file if we got new id
        with open('disco.json', 'w') as outfile:
            dump(config, outfile, indent=4)

    for i in range(packet_num):
        # open port and wait for forwarder to pull the disco data packet to transmit
        disco_to_forwarder(id,payload,listen_port)
        print('packet number', i)
        time.sleep(packet_delay)

    return

def check_msgs(id):
    url = "https://discomode.io/api/msg?id="+str(id)

    try:
        data=requests.get(url=url, headers=headers)
        data=data.json()
    except JSONDecodeError:
        logging.exception("disco_id not found")
        return

    logging.info('get msg packet %s from %s', data, url)
    return data

if __name__ == "__main__":
    parser = argparse.ArgumentParser("disco mode client", add_help=True)

    parser.add_argument('-n', '--number', help='number of packets to send, default=6', default=1, type=int)
    parser.add_argument('-d', '--delay', help='delay in seconds between packets, default=5', default=1, type=int)
    parser.add_argument('-p', '--payload', help='payload to be sent as string, default=30', default='30', type=str)
    parser.add_argument('-i', '--interval', help='polling interval in seconds to check for commands, default=0',default=60,type=int)
    parser.add_argument('-m', '--miner', help='name of the docker container or ip and port of miner, default=miner:4467',default='miner:4467',type=str)

    args = parser.parse_args()
    packet_num=args.number
    packet_delay=args.delay
    payload=args.payload
    poll=int(args.interval)
    miner=str(args.miner)

    miner_rpc = mrpc.mrpc(miner)

    # open json config file for config
    with open('disco.json') as json_file:
        config = load(json_file)
    # getting port to listen on and hs addr to associate with disco id
    listen_port = config['listen_port']
    hotspot_addr = config['hotspot_addr']
    id = config['disco_id']

    # get new disco id if one not found in config
    if id == None or id == '':
        logging.info('no discovery id found. getting new id')
        if hotspot_addr == None or hotspot_addr == '':
            logging.info('no hotspot addr found. using miner rpc to lookup')

            hotspot_addr = miner_rpc.address()

        id = get_disco_id(hs_addr=hotspot_addr)
        config['disco_id'] = id
        config['hotspot_addr'] = hotspot_addr

        # save back to file if we got new id
        with open('disco.json', 'w') as outfile:
            dump(config, outfile, indent=4)

    # if the polling interval is set then run forever
    if poll > 0:
        while(True):
            msg = check_msgs(config['disco_id'])
            if msg:
                print('msg',msg)
                packet_num = msg['disco']['num']
                packet_delay = msg['disco']['delay']
                disco_session(packet_num,packet_delay,payload)
            time.sleep(poll)

    # if not polling just use environment variables and run once
    disco_session(packet_num,packet_delay,payload)


