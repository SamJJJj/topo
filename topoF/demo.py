import socket
import struct
import nmap
from redis import StrictRedis

ip = '192.168.0.1'

def traceroute(ip):
   for ttl in range(1, 30):
      s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
      s.settimeout(2)
      try:
         s.connect((ip, 80))
      except (socket.error, socket.timeout) as err:
            print ('ttl=%02d: %s' % (ttl, err))
            continue
      finally:
         s.close()
r = StrictRedis(host='localhost', port=6379, db=0)
print(r.keys())
r.close()