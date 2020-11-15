import socket
import os
import sys
import time


def cls(): return os.system('cls')


def print_help():
    print("You must provide 3 parameters:")
    print("1) ip address or hostname")
    print("2) start port")
    print("3) end port")
    print("Example: main.py scanme.nmap.org 1 1024")
    print("Argument given are:", sys.argv[1:])
    sys.exit()


def scan_host(host, startPort, endPort):
    # list of port and relative service name
    openPorts = []
    socket.setdefaulttimeout(0.01)
    startPort = int(startPort)
    endPort = int(endPort)

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

    # checking if startPort isn't bigger than endPort
    if startPort > endPort:
        print("Error: start port can't be bigger than end port!")
        sys.exit()
    # checking if the startPort and endPort are valid
    if startPort < 0 or endPort > 65535:
        print("Error: invalid port number!")
        sys.exit()

    print("Starting port scan of host: {}({})".format(host, fqdn))
    print("Scanning all the ports between", startPort, "and", endPort)

    # this is to get the execution time
    startTime = time.time()

    for port in range(startPort, endPort+1):
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


def main():
    # checking if the arguments are enough
    if len(sys.argv) != 4:
        print_help()

    cls()
    openPorts = scan_host(sys.argv[1], sys.argv[2], sys.argv[3])
    print("Found {} ports open".format(len(openPorts)))
    if len(openPorts) >= 1:
        print("Port \t Service Name")
        for port, serviceName in openPorts:
            print(port, "\t", serviceName)


if __name__ == '__main__':
    try:
        main()
    # in case of CTRL+C pressed
    except KeyboardInterrupt:
        print('Interrupted')
        os._exit(0)
