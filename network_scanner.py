import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',help = "Target IP or Range of IP")
    option = parser.parse_args()
    return option


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether()
    client_list = []
    arp_broadcst = broadcast/arp_request
    answered_list = scapy.srp(arp_broadcst, timeout=1,verbose=False)[0]
    for each_element in answered_list:
        client_dict = {"ip":each_element[1].psrc, "MAC":each_element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
def print_result(result_list):
    print("-"*55)
    print("\tIP address\t\tMAC address")
    print("-"*55)
    for num, client in enumerate(result_list, start=1):
        print(str(num)+'\t'+client['ip']+ "\t\t"+ client['MAC'])

option = get_arguments()
scan_result = scan(option.target)
print_result(scan_result)
