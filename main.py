import socket
import os
import sys
import time
import argparse


def cls(): return os.system('cls')


def scan_host(host, ports_to_scan):
    # list of port and relative service name
    openPorts = []
    socket.setdefaulttimeout(0.01)

    # trying to obtain the ip address
    try:
        ip = socket.gethostbyname(host)
    except:
        print("Error: ip invalid or can't resolve the host name in IP address!")
        sys.exit()

    # trying to obtain the FQDN
    try:
        fqdn = socket.getfqdn(host)
    except:
        fqdn = host

    print("Starting port scan of host: {}({})".format(host, fqdn))

    # this is to get the execution time
    startTime = time.time()

    for port in ports_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # if the port is open
        if not sock.connect_ex((ip, port)):
            try:
                # get the service name for the port
                serviceName = socket.getservbyport(port, "tcp")
            except:
                serviceName = ""
            openPorts.append((port, serviceName))
        sock.close()

    executionTime = round((time.time() - startTime), 2)
    print("Scan finished in {} seconds\n".format(executionTime))
    return openPorts

# function to get a nice list of ports to scan from the terminal argument


def inflatePortList(portlist_raw_string):
    range_min_max = []
    inflated_port_list = []

    portlist_raw_list = portlist_raw_string.split(',')

    # for every port number in the list
    for port in portlist_raw_list:
        if port != '':
            # if the dash symbol is present, it's a range
            if (port.find("-") != -1):
                # adding the range of ports in a list
                range_min_max.append(port.split('-'))
            else:
                # if the port doesn't contain letters
                if port.isdigit():
                    port = int(port)
                    if port >= 0 and port <= 65535:
                        inflated_port_list.append(port)

    # for every range to create
    for range_to_create in range_min_max:
        min, max = int(range_to_create[0]), int(range_to_create[1])

        for port in range(min, max+1):
            if port >= 0 and port <= 65535:
                inflated_port_list.append(port)

    # remove duplicates and sort the list
    inflated_port_list = sorted(set(inflated_port_list))

    return(inflated_port_list)


def main():

    parser_usage = '''Usage:
    main.py -p21 192.168.1.1
    main.py -p21,80-90 192.168.1.1
    main.py -p 21,80-90 192.168.1.1
    main.py --port 21 192.168.1.1
    main.py --port 21,80-90 192.168.1.1
    main.py --port 21,80-90 192.168.1.1
    \nEnjoy'''

    parser = argparse.ArgumentParser(
        description="A simple port scanner tool", usage=parser_usage)
    parser.add_argument("ipaddress", help="The IP address you want to scan")
    parser.add_argument(
        "-p", "--port", help="A list of ports to scan", required=True, dest="ports", action="store",)
    args = parser.parse_args()

    cls()

    ports_to_scan = inflatePortList(args.ports)
    if len(ports_to_scan):
        openPorts = scan_host(args.ipaddress, ports_to_scan)
        print("Found {} ports open".format(len(openPorts)))
        if len(openPorts) >= 1:
            print("Port \t Service Name")
            for port, serviceName in openPorts:
                print(port, "\t", serviceName)
        else:
            print("No valid ports found")


if __name__ == '__main__':
    try:
        main()
    # in case of CTRL+C pressed
    except KeyboardInterrupt:
        print('Interrupted')
        os._exit(0)
    except Exception as e:
        print(e)
