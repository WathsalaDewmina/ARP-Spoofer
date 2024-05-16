# ARP Spoofer

## Benefits of ARP Spoofer in Cyber Security

ARP spoofing, also known as ARP poisoning, is a technique used by attackers to intercept network traffic between two hosts by forging ARP (Address Resolution Protocol) messages. While ARP spoofing is often associated with malicious activities, it can also be used for legitimate purposes in cyber security, such as network monitoring, troubleshooting, and penetration testing. By spoofing ARP packets, security professionals can analyze network traffic, detect vulnerabilities, and strengthen network defenses.

## Installation

1. **Download the Source Code:**
    - Clone the repository to your local machine using the following command:
        ```sh
        git clone https://github.com/your-username/arp-spoofer.git
        ```

2. **Install Dependencies:**
    - Ensure you have [pip](https://pypi.org/project/pip/) installed on your machine.
    - Install the required Python module `scapy` using the following command:
        ```sh
        pip3 install scapy
        ```

## Running the Script

1. **Help Screen:**
    - To view the help screen of the script, execute the following command in your terminal:
        ```sh
        python3 arpspoofer.py -h
        ```

2. **Run the Script:**
    - Execute the following command in your terminal to run the ARP spoofer:
        ```sh
        python3 arpspoofer.py -t <victim_ip_addr> -r <gateway_address>
        ```

    - Replace `<victim_ip_addr>` with the IP address of the victim's machine and `<gateway_address>` with the IP address of the gateway/router.

### Examples

Spoof ARP packets to intercept traffic between victim machine (IP: 192.168.8.155) and router (IP: 192.168.9.1):

```sh
python3 arpspoofer.py -t 192.168.8.155 -r 192.168.9.1
