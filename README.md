# discoclient
This is a client to run discovery(disco) mode on a Helium hotspots. Disco mode sends packets from a hotspot to be received and reported by neighbouring hotspots. This can be useful to test your hotspot, antenna or antenna placement

# how to run it
This disco client runs in parallel with the helium miner on the hotspot. When invoked it acts as a lorawan network server while it delivers the disco packet to the forwarder at which point this code is complete and exits. It only responds the the PULL_DATA when polled by the packet forwarder. If you want to run the miner and this disco client some kind of packet multiplexer is required to handle running a single packet forwarder with the miner and this client. The chirpstack packet multiplexer or the helium middleman software both should work but chirpstack is preferred as it does not alter the packet metadata.

Add your port and hotspot address to the disco.json configuration file. The port is used to listed to the forwarder(multiplexer) on so make sure that matches the chirpstack multiplexer config. Leave the disco id field empty and that will automatically be filled out by when the code runs.

# first time run
When this code runs, if the disco id field is blank, it will create a get request discomode.io/api/id? and get a new disco id which is written to the disco.json config file. With this id the actual disco packet to be transitting via RF is obtained with a get to the discomode.io/api/disco? endpoint. Next, the client listens on the port setup in the config file for a PULL_DATA from the packet forward to deliver the disco packet to the RF concentrator to be sent. Once the packet has been delivered to the concentrator this code is complete and closes. If run again with the disco id populated it will only need to grab a new packet from /disco? endpoint and pass it to forwarder to transmit.

# viewing results
The json results from the disco packet transmission can be viewed discomode.io/api/hotspots?id=your_disco_id 

A map view is available from discomode/io/api/map?id=your_disco_id

The above endpoints will provide the last packet only. If you want to view older packets as well add &last=2 to view the latest 2 disco packets, &last=3, etc.

# how it works
The server discomode.io generates and provides packets for the client(this software) running on the hotspot. Disco mode uses standard LoRaWAN packets and infrastrure to collect and report the packets transmitted by the hotspot.

