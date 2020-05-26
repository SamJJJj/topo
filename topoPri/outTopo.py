import json
import socket


def getLocalAddress():
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

    return linkList,dataList


if __name__ == '__main__':
    # outJson()
    pass