# vpn plugin

- a Mach-O library (dylib)
- will be loaded by vpnagent when the user starting an vpn connection of this registered type
- access the SystemConfiguration to get service information associated with the ServiceID
- connect to vpn server and setup tunnel
- register a service entry in SystemConfiguration dynamic store
- override default to pass all traffic (except the vpn server) to vpn connection
- read packets from utun fd and send over vpn tunnel
- write ip packets from vpn tunnel to utun fd
