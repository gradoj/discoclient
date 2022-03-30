# discoclient
This is a client to run discovery(disco) mode on a Helium hotspots. Disco mode sends packets from a hotspot to be received and reported by neighbouring hotspots. This can be useful to test your hotspot and antenna, optimize antenna placement, verify functionality of neighboring hotspots,etc

# how to run it
This disco client runs in parallel with the helium miner on the hotspot. When invoked it acts as a lorawan network server while it delivers the disco packet to the forwarder at which point this code is complete and exits. It only responds the the PULL_DATA when polled by the packet forwarder. If you want to run the miner and this disco client some kind of packet multiplexer is required to handle running a single packet forwarder with the miner and this client. The chirpstack packet multiplexer or the helium middleman software both should work but chirpstack is preferred as it does not alter the packet metadata.

Add your listening port to the disco.json configuration file. The port is used to listed to the forwarder(multiplexer) on so make sure that matches the chirpstack multiplexer config. You can leave the disco id and hotspot_addr fields empty and that will automatically be filled out by when the code runs.

# how it works
The server discomode.io generates and provides packets for the client(this software) running on the hotspot. Disco mode uses standard LoRaWAN packets and infrastrure to collect and report the packets transmitted by the hotspot. Discoclient acts as a bridge between discomode.io and the lorawan packet forwarder running on the hotspots so is responsible for getting a disco id(lorawan sensor id), obtaining the disco packet, and conveying that packet to the forwarder to be transmitted.

## get id
discomode.io/api/id?hs_addr=your_hotspot_address
This links your hotspot address to a disco id to view results. If the disco id field is blank in the disco.json, this client will create a get request and populate a new disco id in disco.json config file. 

## get packet and send
discomode.io/api/disco?id=your_disco_id
This endpoint will return the disco packet to be trasmitted via RF with the disco id obtained above. Next, the client listens on the port setup in the config file for a PULL_DATA from the packet forward to deliver the disco packet to the RF concentrator to be sent. Once the packet has been delivered to the concentrator this code is complete and closes. If run again with the disco id populated it will only need to grab a new packet from /disco? endpoint and pass it to forwarder to transmit.

discomode.io/api/disco?id=your_disco_id&payload=deadbeef
The payload to be transmitted can be optionally be passed in as hex strings. This isn't really complete yet as it isn't encrypted as per lorawan specs with the appskey nor is there any way to retrieve it.  

## view results

dash.discomode.io

All data packets are paid for through the Helium router and collected. The disco results can be view through a visual map view or json list of hotspots.

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
-Use all valid channels on plans. currently hardcoded using a single channel

