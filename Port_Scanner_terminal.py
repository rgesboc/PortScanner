import sys
import socket
from datetime import datetime
import pyfiglet
import ipaddress
import argparse
import textwrap

default_ports = [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 500, 554, 587, 993, 1434, 3389, 5900, 8008, 8080]

class PortScanner:
    def __init__(self,args):
        self.args = args

    def run(self):
        ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
        print("-" * 70)
        print(ascii_banner)
        print("-" * 70)
        targets = self.parse_targets()
        ports = self.parse_ports()
        self.scan(targets,ports)

    def parse_targets(self):
        targets = []
        try:
            if '/' in self.args.target:
                targets = list(ipaddress.ip_network(self.args.target, False).hosts())
            elif '-' in self.args.target:
                octets = self.args.target.split('.')
                target_range = octets[3].split('-')
                lower_range, upper_range = int(target_range[0]), int(target_range[1])
                for target in range(lower_range,upper_range+1):
                    target_string = str(octets[0]) + '.' + str(octets[1]) + '.' + str(octets[2]) + '.' + str(target)
                    targets.append(socket.gethostbyname(target_string))
            else:
                targets.append(socket.gethostbyname(self.args.target))
            return targets
        except:
            print("Invalid target input. Exiting.")
            sys.exit()

    def parse_ports(self):
        ports = []
        try:
            # Specific ports
            if "," in self.args.port:
                split_individual_ports = self.args.port.split(",")
                for port in split_individual_ports:
                    ports.append(int(port))
            # Port Range
            elif "-" in self.args.port:
                start_port, end_port = self.args.port.split("-")
                start_port = int(start_port)
                end_port = int(end_port)
                for port in range(start_port, end_port +1):
                    ports.append(port)
            elif type(self.args.port) == list:
                ports = self.args.port
            # Single Port
            else:
                ports.append(int(self.args.port))
            return ports
        except TypeError:
            print("Invalid port input. Exiting.")
            sys.exit()
        
    def scan(self,targets,ports):
        total_start = datetime.now()
        total_hits = 0
        ip_hits = []
        print_targets = ''
        print_ports = ''
        wrapper = textwrap.TextWrapper(width = 70)
        ports.sort()

        for target in targets:
            if targets.index(target) < len(targets)-1:
                print_targets += str(target) + ", "
            else:
                print_targets += str(target)
        print_targets = (f'Scanning Targets: {print_targets}')
        print_targets = wrapper.fill(text = print_targets)
        print(f'{print_targets}\n')

        for port in ports:
            if ports.index(port) < len(ports)-1:
                print_ports += str(port) + ", "
            else:
                print_ports += str(port)
        print_ports = (f'Scanning Ports: {print_ports}')
        print_ports = wrapper.fill(text = print_ports)
        print(print_ports)
        
        try:
            # Iterate through the targets
            for target in targets:
                target = str(target)
                # Time tracking for each target
                time_started = datetime.now()

                # Tracking port states per target
                open_ports = 0
                closed_ports = 0

                # Add banner
                print("-" * 70)
                print(f"Scanning Target: {target}")
                print(f"Scanning started at: {str(time_started)}\n")

                for port in ports:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket.setdefaulttimeout(1)

                    # Returns an error indicator
                    result = s.connect_ex((target,port))
                    if result == 0:
                        port_name = socket.getservbyport(port)
                        print(f'Port open: {port} {port_name}')
                        open_ports +=1
                        if target not in ip_hits:
                            ip_hits.append(target)
                    else:
                        closed_ports+=1
                    s.close()

                print(f"\nOpen ports: {open_ports}")
                print(f"Closed/Unresponsive ports: {closed_ports}")
                time_stopped = datetime.now()
                print(f"Scanning Ended at: {str(time_stopped)}")
                time_elapsed = time_stopped - time_started
                print(f"Time Elapsed was: {str(time_elapsed)}")
            
            total_end = datetime.now()
            total_duration = total_end - total_start
            target_length = len(targets)
            total_hits = len(ip_hits)
            print("-"*70)
            print("=" * 28 + "SCAN FINISHED!" + "=" * 28 + "\n")
            print(f"Scanned {str(target_length)} total targets and got hits on {str(total_hits)} of them:")
            ip_hits.sort()
            for ips in ip_hits:
                print(ips)
            print(f"\nThe total duration of the scan was {total_duration}\n")

        except KeyboardInterrupt:
            print("\nKeyboard interrupt. Exiting Program.")
            sys.exit()
        except socket.gaierror:
            print("\nHostname Could Not Be Resolved.")
            sys.exit()
        except socket.error:
            print("\nTarget not responding.")
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent('''Example:
            port_scanner.py -t 192.168.1.1 -p 22 # Single target, single port
            port_scanner.py -t 192.168.1.1-10 -p 1-100 # Target range, port range
            port_scanner.py -t 192.168.1.0/28 -p 22,80,443,995 # Target CIDR range, specific ports
            Leaving the port argument empty will perform a scan on the most commonly used ports
        '''))
    parser.add_argument('-t', '--target', default = '127.0.0.1', help = 'Specified Target(s)')
    parser.add_argument('-p', '--port', help = 'Specified Port(s)')
    args = parser.parse_args()

    if args.port == None:
        args.port = default_ports

    scanner = PortScanner(args)
    scanner.run()