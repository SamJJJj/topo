import MySQLdb
import logging,warnings
import json
from scapy.all import *
from redis import StrictRedis
from multiprocessing import Process, Lock, Queue, Pool


# warnings.filterwarnings("ignore", category = DeprecationWarning)


ips = []
rawTrace = {}

def getLocalAddress():
    """
    查询本机ip地址
    :return:
    """
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(('8.8.8.8',80))
        ip=s.getsockname()[0]
    finally:
        s.close()

    return ip

def getIps():
    conn = MySQLdb.connect(host='localhost',port=3306,db='device_perception',user='root',passwd='anwei')
    cs1 = conn.cursor()
    cs1.execute('select * from sy_ipMac')
    conn.commit()
    cs1.close()
    conn.close()
    for i in cs1:
        ips.append(i[1])

def cons_graph():
    data = {}
    with open('rawTrace.json', 'r') as f:
        jsonStr = f.readlines()
    for line in jsonStr:
        tmpDict = json.loads(line)
        for k in tmpDict:
            if(k not in data.keys()):
                data[k] = tmpDict[k]
    graph = {}
    localIp = getLocalAddress()
    graph[localIp] = []
    for k in data:
        print(k,data[k])
        if (k != list(data[k].values())[-1][0] or len(data[k]) == 30):
            continue
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

def outJson(adjList):
    id2Ip = {}
    linkList = []
    dataList = []
    localIp = getLocalAddress()
    for e in adjList[localIp]:
        if e in adjList.keys():
            id2Ip[0] = e
            break
    if(localIp not in adjList[id2Ip[0]]):
        adjList[id2Ip[0]].append(localIp)
    for e in adjList[localIp]:
        if(e not in adjList[id2Ip[0]]):
            adjList[id2Ip[0]].append(e)
    del adjList[localIp]
    for k in adjList.keys():
        if (k not in id2Ip.values()):
            id2Ip[len(id2Ip)] = k
        for v in adjList[k]:
            if (v not in id2Ip.values()):
                id2Ip[len(id2Ip)] = v
    ip2Id = {v: k for k, v in id2Ip.items()}
    for k in adjList.keys():
        for v in adjList[k]:
            linkList.append({'target': ip2Id[k], 'source': ip2Id[v]})
    dataList.append({'id':0, 'value':id2Ip[0]})
    dataList[0]['name'] = '路由'
    dataList[0]['symbol'] = 'rect'
    dataList[0]['category'] = 0
    dataList[0]['symbolSize'] = 30
    # print(id2Ip[0])
    # print(dataList[0])
    for i in range(1, len(id2Ip)):
        dataList.append({'id': i, 'value': id2Ip[i]})
        if (i > 0 and (id2Ip[i] in adjList.keys())):
            dataList[i]['name'] = '路由'
            dataList[i]['symbol'] = 'rect'
            dataList[i]['category'] = 0
            dataList[i]['symbolSize'] = 30
        else:
            dataList[i]['name'] = '终端'
            dataList[i]['symbol'] = 'circle'
            dataList[i]['category'] = 1
            dataList[i]['symbolSize'] = 30
    return "'link':{},'code':200,'data':{}".format(linkList, dataList)
    #return linkList,dataList


def getTrace(ip):
    ans, unans = traceroute(ip, dport = [80], retry = -2, timeout = 3)
    (k,v), = ans.get_trace().items()
    rawTrace[k] = v
    lock.acquire()
    with open("rawTrace.json", "a") as f:
        json.dump(rawTrace, f)
        f.write("\n")
    # with open("rawTrace1.json", "a") as f:
    #     f.write(str(ans.get_trace()).replace("'", '"') + "\n")
    lock.release()
    # v, = ans.values()


def init(l):
	global lock
	lock = l


def main():
    getIps()
    # ips = ['192.168.0.1', '192.168.0.8', '192.168.0.62', '192.168.1.131']
    lock = Lock()
    p = Pool(5, initializer = init, initargs = (lock, ))
    for ip in ips:
        p.apply_async(getTrace, args = (ip, ))
    p.close()
    p.join()
    cons_graph()


def test():
    adjList = {}
    with open("topo.json", "r") as f:
        adjList = json.load(f)
    print('-------------------------------------------------')
    print(outJson(adjList))


# main()
# test()
cons_graph()


#ans,unans=sr(IP(dst="192.168.0.1",ttl=(1,10),id=RandShort())/TCP(flags=0x2))

# ans, unans = traceroute('192.168.0.1', dport = [80, 443], retry = -2)

# print(ans.get_trace())
