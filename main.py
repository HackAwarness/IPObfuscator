import re
print("Outil d'obfuscation d'adresse IP\n")
print("Utile pour le bypass de firewall\n\n")
IP = input("Entrer une adresse IP (ipv4):\n>>")


def inputIP(IP):
    regex = re.compile(
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return regex.findall(IP)


def ip2hex(ip):
    result = ""
    ipDict = ip.split(".")
    for i in ipDict:
        toHex = int(i, 16)
        result += hex(toHex)+"."
    result = result[0:-1]
    return result


def ip2hexIndex(ip, index):
    result = ""
    ipDict = ip.split(".")
    for i in ipDict:
        if i == ipDict[index]:
            toHex = int(i, 16)
            result += hex(toHex) + "."
        else:
            result += i + "."
    result = result[0:-1]
    return result


def ip2oct(ip, zeros=1):
    result = ""
    ipDict = ip.split(".")
    for i in ipDict:
        result += zeros*"0"+oct(int(i))[2:]+"."
    result = result[0:-1]
    return result


def ip2octIndex(ip, index, zeros=1):
    result = ""
    ipDict = ip.split(".")
    for i in ipDict:
        if i == ipDict[index]:
            result += zeros*"0"+oct(int(i))[2:] + "."
        else:
            result += i + "."
    result = result[0:-1]
    return result


def toDword(ip, level):
    result = ""
    n = ip.split(".")
    dword = (int(n[0]) * 16777216) + (int(n[1]) * 65536) + (int(n[2]) * 256) + int(n[3]) + (int(level) * 4294967296)
    result = dword
    return result


if __name__ == '__main__':
    if inputIP(IP):
        print(inputIP(IP))
        print("Resutats: \n\n")
        print("[!] HEXADECIMAL: ")
        print("[+] To Hex :"+ip2hex(IP))
        print("[+] To Hex index 1: "+ip2hexIndex(IP,0))
        print("[+] To Hex index 2: "+ip2hexIndex(IP,1))
        print("[+] To Hex index 3: "+ip2hexIndex(IP,2))
        print("[+] To Hex index 4: "+ip2hexIndex(IP,3))
        print("\n")
        print("[!] OCTAL: ")
        print("[+] To Oct :" + ip2oct(IP))
        print("[+] To Oct index 1: " + ip2octIndex(IP, 0))
        print("[+] To Oct index 2: " + ip2octIndex(IP, 1))
        print("[+] To Oct index 3: " + ip2octIndex(IP, 2))
        print("[+] To Oct index 4: " + ip2octIndex(IP, 3)+"\n")
        print("[!] To Dword: ")
        print("[+] DWORD : "+ str(toDword(IP,0)))