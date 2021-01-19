import nmap
scanner = nmap.PortScanner()

print("this is a simple scanner")
print("<=============================>")

ip = input("please input the address you want to scan")
print("you entered this ip", ip)
type(ip)

resp = input("""\n what type of scan you want to use
                1)SYN ACK SCAN
                2)UDP SCAN
                3)COMPREHENSIVE SCAN \n""")
print("you have selected option:", resp)
if resp == '1':
    print("nmap version ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("ip status: ", scanner[ip].state())
    print(scanner[ip].all_protocols())
    print("open ports: ", scanner[ip]['tcp'].keys())

elif resp == '2':
    print("nmap version ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("ip status: ", scanner[ip].state())
    print(scanner[ip].all_protocols())
    print("open ports: ", scanner[ip]['udp'].keys())
elif resp == '3':
    print("nmap version ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("ip status: ", scanner[ip].state())
    print(scanner[ip].all_protocols())
    print("open ports: ", scanner[ip]['tcp'].keys())
elif resp == '4':
    print("Please enter valid ip")
    