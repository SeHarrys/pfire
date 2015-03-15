# pfire iptables script

    pfire a simple script to iptables, the configuration is in json format

    Services TCP & UDP depends on the police used

    Police:
     paranoid : All TCP SYN and UDP closed only open in the services specified
     server   : All is closed TCP and UDP only low ports
     open     : All open and only services specfied are closed
     neutral  : Nothing to do.. nifu nifa
     intranet : All connections are welcome to the specific dev only
     secure   : All ports are syn closed and only open the services

    Services   : Ports in used ( depending of the police )
    Redirect   : Redirect port to another ip:port
    Limits     : Limits port connections/times
    block_from : Block port TCP/UDP from IP
    block_country : Block Range IP of a Country

    Forward    : Enable forwarding
     tproxy    : Transparent proxy

    secure :
     block_tor : Block TOR Network

    iptables -t nat -L -n -v

    pfire read first: '/etc/pfire.conf' next enviroment 'PFIRE' and last check ARGV[0] , the specified file could be a local file or http

    iptables chains
     - blacklist-ip
     - admin-ip               : Allow only connections to this IPs
     - block-country-iso_code : One chain per country
     - block-tor

    - Report
