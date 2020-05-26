import xmltodict
import json
import os
import nmap
import time
import re
import socket
import fcntl
import struct
from collections import OrderedDict
from scapy.all import traceroute



ip = "192.168.0-1.0/24"
onvif = ['normal', 'hik']

class Topo():

    def __init__(self, ip):
        self.scanIp = ip
        self.ips = []
        self.onvifXmlDic = {}
        self.onvifPort = {}
        self.onvifXmlDic['normal'] = """
            <?xml version="1.0" encoding="utf-8"?>
    <Envelope xmlns="http://www.w3.org/2003/05/soap-envelope" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
    <Header>
        <wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">uuid:b268d5d0-655a-4ccc-a10b-2d4a7268bd51</wsa:MessageID>
        <wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
        <wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    </Header>
    <Body>
        <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <Types>aw:NetworkVideoTransmitter</Types>
        <Types>aw:Device</Types>
        </Probe>
    </Body>
    </Envelope>
            """
        self.onvifXmlDic['hik'] = """
            <?xml version="1.0" encoding="utf-8"?>
            <Probe>
            <Uuid>C483AB63-7959-4017-AE5D-9A6D79BF4B80</Uuid>
            <Types>inquiry</Types>
            </Probe>
            """
        self.onvifXmlDic['keda'] = '''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:dn="http://www.onvif.org/ver10/network/wsdl" xmlns:ter="http://www.onvif.org/ver10/error"><SOAP-ENV:Header><wsa:MessageID>urn:uuid:5ec3a542-e5b6-415a-8000-55c8000053d6</wsa:MessageID><wsa:To SOAP-ENV:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action SOAP-ENV:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes></d:Scopes></d:Probe></SOAP-ENV:Body></SOAP-ENV:Envelope>
'''
        self.onvifPort['normal'] = 3702
        self.onvifPort['keda'] = 3702
        self.onvifPort['hik'] = 37020

    #onvif 发现设备
    def discoveryOnvif(self, vendor):
        local_ip = self.getLocalAddress()
        xml_str = self.onvifXmlDic[vendor]

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 64)
        s.bind((local_ip, 10000))

        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton("239.255.255.250") + socket.inet_aton(local_ip))

        s.setblocking(False)

        s.sendto(xml_str.encode(), ("239.255.255.250", self.onvifPort[vendor]))
        now = beg = time.time()
        while True:
            try:
                data, address = s.recvfrom(4096)
            except Exception as e:
                #print(e)
                now = time.time()
                if(now - beg >= 5):
                    break
                pass
            else:
                now = beg = time.time()
                if(address[0] not in self.ips):
                    self.ips.append(address[0])
                print(data)
                print(address)
                # print(data)
    #获得本机ip ifname 是网卡名字 wlp3s0
    def getLocalAddress(self):
        """
        查询本机ip地址
        :return:
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        finally:
            s.close()

        return ip
    #用nmap的ping扫描
    def getDataPing(self):
        nm = nmap.PortScanner()
        result = []
        for i in range(0, 5):
            tmpRes = nm.scan(hosts = self.scanIp, arguments = '-sn')
            for e in tmpRes['scan'].keys():
                if not e in result:
                    result.append(e)
        # return result #list(result['scan'].keys())
        self.ips = result
    #获得图数据
    def cons_graph(self):
    # def cons_graph():
        res,unans = traceroute(self.ips, dport=[80,443],retry=-2)
        data = res.get_trace()
        graph = {}
        localIp = self.getLocalAddress()
        graph[localIp] = []
        for k in data:
            # print(k, "---", data[k])      |       == 1 or list(data[k].values())[0][1] == False
            if(len(list(data[k].keys())) == 1 and (k not in graph[localIp])):
                #print(data[k])
                graph[localIp].append(k)
            else:
                pre = localIp
                for kk in data[k]:
                    if (data[k][kk][0] not in graph.keys()) and (data[k][kk][0] != list(data[k].values())[-1][0]):
                        graph[data[k][kk][0]] = []
                    # print(graph.keys())
                    # print(data[k][kk][0])
                    if(pre != data[k][kk][0] and (data[k][kk][0] not in graph[pre])):
                        graph[pre].append(data[k][kk][0])
                    pre = data[k][kk][0]
        with open('topo.json', 'w') as f:
            json.dump(graph, f)
    #获得topo.json
    # 先用onvif发现(只能发现当前网段)，然后ping扫描5次，最后用得到的ip去traceroute，最后构建邻接表
    def getTopo(self):
        # for vendor in self.onvifXmlDic:
        #     self.discoveryOnvif(vendor)
        #     print(self.ips)
        self.getDataPing()
        self.cons_graph()


def getHostSys(ip):
    nm = nmap.PortScanner()
    type_list = ['iPhone', 'HUAWEI', 'Xiaomi', 'OPPO', 'HONOR', 'android']
    try:
        tmpRes = nm.scan(hosts=ip, arguments="-O --host-timeout 120")
        # print(tmpRes)
        sysInfo = tmpRes['scan'][ip]['osmatch'][0]['name']
        hostname = tmpRes['scan'][ip]['hostnames'][0]['name']
        termType = ""
    except:
        sysInfo = ''
        hostname = ''
        termType = ''
        pass
    if(('Linux' in sysInfo) or ('Windows' in sysInfo) or ('Mac' in sysInfo)):
        termType = "server"
    if 'router' in hostname:
        termType = "router"
    for i in type_list:
        if i in hostname:
            termType = 'Mobile devices'
    # return hostname, sysInfo, termType
    return sysInfo, termType
if __name__ == '__main__':
    # ips = getDataPing()
    # print(len(ips))
    # cons_graph(ips)
    # ip = "192.168.0-1.0/24"
    # topo = Topo(ip)
    # topo.getTopo()
    # topo.ips.append('192.168.0.242')
    # topo.getDataPing()
    # topo.cons_graph()
    # topo.discoveryOnvif('keda')
    # topo.getDataPing()
    # # print(topo.ips)
    # print(len(topo.ips))
    a = getHostSys('192.168.0.19')
    # a = getHostSys('192.168.0.197')
    print(a)
    pass
