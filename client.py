import socket
import struct
import random

def dns_query(qname, qtype, server_ip, port=53):
    query_id = random.randint(0, 65535)
    header = struct.pack('!HHHHHH', query_id, 0x0000, 1, 0, 0, 0)
    encoded_qname = b''
    for part in qname.split('.'):
        encoded_qname += struct.pack('!B', len(part)) + part.encode('ascii')
    encoded_qname += b'\x00'
    qtype_code = 1 if qtype == 'A' else 2
    question = encoded_qname + struct.pack('!HH', qtype_code, 1)
    message = header + question

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        try:
            sock.sendto(message, (server_ip, port))
            data, _ = sock.recvfrom(512)
            return data
        except:
            return None

def parse_response(data):
    if not data:
        return None
    try:
        ancount = struct.unpack('!H', data[6:8])[0]
        authorities = []
        additionals = []
        offset = 12
        # 跳过问题部分
        while data[offset] != 0:
            offset += 1 + data[offset]
        offset += 5
        # 解析回答部分
        for _ in range(ancount):
            while data[offset] & 0xC0 == 0xC0:
                offset += 2
            while data[offset] != 0:
                offset += 1 + data[offset]
            offset += 2 + 2 + 4 + 2
            if data[offset-2:offset] == b'\x00\x01':  # A记录
                ip = socket.inet_ntoa(data[offset:offset+4])
                return ip
            offset += struct.unpack('!H', data[offset-2:offset])[0]
        return None
    except:
        return None

def iterative_resolve(qname):
    # 先查询顶级域名服务器
    tld_response = dns_query(qname, 'A', '192.168.1.101', 53)
    ip = parse_response(tld_response)
    if ip:
        return ip
    # 若顶级无结果，获取根服务器IP并查询
    root_ip = '192.168.1.100'
    root_response = dns_query(qname, 'A', root_ip, 5353)
    ip = parse_response(root_response)
    return ip if ip else 'none'

if __name__ == '__main__':
    domain = 'example.com'
    result = iterative_resolve(domain)
    print(f"{domain} 的IP地址: {result}")