import sys
import socket
from datetime import datetime
import pyfiglet
import ipaddress

def setup():
    ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
    print("-" * 70)
    print(ascii_banner)
    print("-" * 70)
    port_range = False

    while True:
        # Define target
        target_list = []
        try:
            target_input = input("What target(s) do you wish to scan? ")
            if "/" in target_input:
                target_list = list(ipaddress.ip_network(target_input, False).hosts())
            elif "-" in target_input:
                target_input.replace(" ", "")
                octets = target_input.split(".")
                target_range = octets[3].split("-")
                lower_range = int(target_range[0])
                upper_range = int(target_range[1])
                for targets in range(lower_range,upper_range+1):
                    target = str(octets[0]) + "." + str(octets[1]) + "." + str(octets[2]) + "." + str(targets)
                    target_list.append(socket.gethostbyname(target))
            else:
                target_list.append(socket.gethostbyname(target_input))
            break
        except KeyboardInterrupt:
            print("\nKeyboard interrupt. Exiting Program.")
            sys.exit()
        except:
             print("Invalid argument")
             continue

    while True:
        individual_ports = set()
        start_port = 0
        end_port = 0
        # Define ports
        try:
            ports = input("What port range do you wish to scan? ex: 22 or 80,443 or 1-100: ")
            ports.replace(" ", "")

            if "," in ports:
                # specific ports
                split_individual_ports = ports.split(",")
                for ports in split_individual_ports:
                    individual_ports.add(int(ports))
                port_range = False
                break
            elif "-" in ports:
                # port range
                start_port, end_port = ports.split("-")
                start_port = int(start_port)
                end_port = int(end_port)
                port_range = True
                break
            else:
                # single port
                port_range = False
                individual_ports.add(int(ports))
                break
        except KeyboardInterrupt:
            print("\nKeyboard interrupt. Exiting Program.")
            sys.exit()
        except:
             print("Please input a valid port range")

    return target_list, start_port, end_port, individual_ports, port_range

def port_range_scan(start_port, end_port, target_list):

    total_start = datetime.now()
    total_hits = 0
    ip_hits = set()

    try:
        # Iterate through the targets provided
        for target in target_list:
            target = str(target)

            # Time tracking for each target
            time_started = datetime.now()

            # Tracking port states
            open_ports = 0
            closed_ports = 0

            # Add Banner
            print("-" * 50)
            print("Scanning Target: " + target)
            print("Scanning started at:" + str(time_started))
        
            for port in range(start_port,end_port):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                
                # returns an error indicator
                result = s.connect_ex((target,port))
                if result ==0:
                    print(f"Port {port} is open")
                    open_ports+=1
                    ip_hits.add(target)
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
        target_length = len(target_list)
        total_hits = len(ip_hits)
        print("-"*50)
        print("=" * 18 + "SCAN FINISHED!" + "=" * 18 + "\n")
        print(f"Scanned {str(target_length)} total targets and got hits on {str(total_hits)} of them:")
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

def individual_port_scan(individual_ports, target_list):

    total_start = datetime.now()
    total_hits = 0
    ip_hits = set()

    try:
        # Iterate through the targets provided
        for target in target_list:
            target = str(target)

            # Time tracking for each target
            time_started = datetime.now()

            # Tracking port states
            open_ports = 0
            closed_ports = 0

            # Add Banner
            print("-" * 50)
            print("Scanning Target: " + target)
            print("Scanning started at:" + str(time_started))

            # Scan individual ports given
            for port in individual_ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                
                # returns an error indicator
                result = s.connect_ex((target,port))
                if result ==0:
                    print(f"Port {port} is open")
                    open_ports+=1
                    ip_hits.add(target)
                else:
                    closed_ports+=1
                s.close()

            # Output results
            print(f"\nOpen ports: {open_ports}")
            print(f"Closed/Unresponsive ports: {closed_ports}\n")
            time_stopped = datetime.now()
            print(f"Scanning Ended at: {str(time_stopped)}")
            time_elapsed = time_stopped - time_started
            print(f"Time Elapsed was: {str(time_elapsed)}")

        total_end = datetime.now()
        total_duration = total_end - total_start
        target_length = len(target_list)
        total_hits = len(ip_hits)
        print("-"*50)
        print("=" * 18 + "SCAN FINISHED!" + "=" * 18 + "\n")
        print(f"Scanned {str(target_length)} total targets and got hits on {str(total_hits)} of them:")
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

if __name__ == "__main__":
    keep_going = True
    while keep_going:  
        target_list, start_port, end_port, individual_ports, port_range = setup()
        if port_range == True:
            port_range_scan(start_port, end_port, target_list)
        elif port_range == False:
            individual_port_scan(individual_ports,target_list)

        while True:
            choice = input("Would you like to scan again(yes or no)? ").capitalize()
            if choice == "Yes":
                break
            elif choice == "No":
                keep_going = False
                break
            else:
                print("Sorry, that is not a valid response")