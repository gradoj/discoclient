# discoclient
This is a client to run discovery(disco) mode on a Helium hotspots. Disco mode sends packets from a hotspot to be received and reported by neighbouring hotspots. This can be useful to test your hotspot and antenna, optimize antenna placement, verify functionality of neighboring hotspots,etc

![dash.discomode.io](https://github.com/gradoj/discoclient/blob/main/screenshots/screen_disco.png)
![dash.discomode.io](https://github.com/gradoj/discoclient/blob/main/screenshots/screen_map.png)

## how to run
There are various method to get the disco client running on your hotspot.
### Ansible
This branch of HeliumDIY has the disco client enabled. Follow readme and create your own sd card.
https://github.com/gradoj/helium_ansible
[https://github.com/gradoj/helium_ansible](https://github.com/gradoj/helium_ansible)

### Docker 
Each release can be pulled from the github container repository
ghcr.io/gradoj/discoclient:latest

### Docker Compose
There is a basic docker-compose.yml in github that you can integrate into your system.

## how it works

![high level diagram](https://github.com/gradoj/discoclient/blob/main/screenshots/high_level.png)

This disco client runs in parallel with the helium miner on your hotspot. It acts as a lorawan network server while it delivers the disco packet to the forwarder at which point this code is complete and exits. It only responds the the PULL_DATA when polled by the packet forwarder. If you want to run the miner and this disco client some kind of packet multiplexer is required to handle running a single packet forwarder with the miner and this client. The chirpstack packet multiplexer or the helium middleman software both should work but chirpstack is preferred as it does not alter the packet metadata.

The server discomode.io generates and provides packets for the client(this software) running on the hotspot. Disco mode uses standard LoRaWAN packets and infrastrure to collect and report the packets transmitted by the hotspot. Discoclient acts as a bridge between discomode.io and the lorawan packet forwarder running on the hotspots so is responsible for getting a disco id(lorawan sensor id), obtaining the disco packet, and conveying that packet to the forwarder to be transmitted.

### Start disco mode from dash.discomode.io
If this client is run with the --interval switch it will poll dash.discomode.io for a message to begin a disco session.  

### Start disco mode from hotspot
Instead of using dash.discomode discovery mode can be started directly from the hotspot.  

    parser.add_argument('-n', '--number', help='number of packets to send, default=6', default=1, type=int)
    parser.add_argument('-d', '--delay', help='delay in seconds between packets, default=5', default=1, type=int)
    parser.add_argument('-p', '--payload', help='payload to be sent as string, default=30', default='30', type=str)
    parser.add_argument('-i', '--interval', help='polling interval in seconds to check for commands, default=0',default=60,type=int)
    parser.add_argument('-m', '--miner', help='name of the docker container or ip and port of miner, default=miner:4467',default='miner:4467',type=str)

## Viewing Results
### Map view
discomode.io/api/map?id=your_disco_id

### json hotspot results
discomode.io/api/hotspots?id=your_disco_id

optional parameters for the map or json view 
&last=3 returns the last 3 disco packet results
&fcnt=42 returns the disco packet with frame count of 42 

# Yet to be completed

-Encrypt the payload with appskey on backend before generating mic
-Support multiple regions/channel plans. Currently only supports US915


