from concurrent.futures.thread import ThreadPoolExecutor
import socket
import os
import sys
import time
import argparse
import concurrent.futures


class PScan:
    def __init__(self):
        self.open_ports = []
        self.portlist_raw_string = ""
        self.remote_host = ""
        self.remote_host_fqdn = ""
        self.remote_ip = ""
        self.number_of_open_ports = 0

    def get_ports(self, portlist_raw_string):
        """
        Take a string with ports and splits into single port, then calculates the range of ports to check
        """
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
        return inflated_port_list

    def scan_port(self, remote_host, port):
        """
        New function to scan ports
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        # if port is open
        if not sock.connect_ex((remote_host, port)):
            try:
                # get the service name for the port
                serviceName = socket.getservbyport(port, "tcp")
            except:
                serviceName = ""

            sock.close()
            self.number_of_open_ports += 1
            print(port, "\t", serviceName)

    def scan_host(self, remote_host, ports_to_scan):
        """
        Scans a host to check if the given ports are open
        """

        # trying to obtain the ip address
        try:
            ip = socket.gethostbyname(remote_host)
        except:
            print("Error: ip invalid or can't resolve the host name in IP address!")
            sys.exit()

        # trying to obtain the FQDN
        try:
            fqdn = socket.getfqdn(remote_host)
        except:
            fqdn = remote_host

        print("Starting port scan of host: {} ({})".format(remote_host, fqdn))

        # this is to get the execution time
        startTime = time.time()

        # using multithreading to scan multiple ports simultaneously
        with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
            {executor.submit(self.scan_port, remote_host, port): port for port in ports_to_scan}

        # i wait for all the threads to complete
        executor.shutdown(wait=True)
        # calculating execution time
        executionTime = round((time.time() - startTime), 2)

        # printing some info
        print("\nScan finished in {} seconds".format(executionTime))
        print("Found {} open ports!".format(self.number_of_open_ports))

    def initialize(self):
        self.ports_to_scan = self.get_ports(self.portlist_raw_string)
        if len(self.ports_to_scan):
            self.open_ports = self.scan_host(
                self.remote_host, self.ports_to_scan)

    def parse_args(self):
        parser_usage = '''main.py -p 21 192.168.1.1
        main.py -p 21,80-90 192.168.1.1
        main.py --port 21 192.168.1.1
        main.py --port 21,80-90 192.168.1.1'''

        parser = argparse.ArgumentParser(
            description="A simple port scanner tool", usage=parser_usage)
        parser.add_argument(
            "ipaddress", help="The IP address you want to scan")
        parser.add_argument(
            "-p", "--port", help="A list of ports to scan", required=True, dest="ports_to_scan", action="store",)
        # printing help if no argument given
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        arguments = parser.parse_args()
        self.remote_host, self.portlist_raw_string = arguments.ipaddress, arguments.ports_to_scan


if __name__ == '__main__':
    pscan = PScan()
    pscan.parse_args()
    pscan.initialize()
