import socket
import struct
import random

# DNS记录类型
DNS_TYPE_A = 1
DNS_TYPE_NS = 2

# 模拟的DNS记录
dns_records = {
    'example.com': {
        'A': ['93.184.216.34'],
        'NS': ['ns1.example.com']
    },
    'ns1.example.com': {
        'A': ['192.0.2.1']
    },
    'com': {
        'NS': ['a.gtld-servers.net']
    },
    'a.gtld-servers.net': {
        'A': ['192.5.6.30']
    }
}

def build_dns_response(query_id, qname, qtype):
    header = struct.pack('!HHHHHH', query_id, 0x8180, 1, 1, 0, 0)
    encoded_qname = b''
    for part in qname.split('.'):
        encoded_qname += struct.pack('!B', len(part)) + part.encode('ascii')
    encoded_qname += b'\x00'
    question = encoded_qname + struct.pack('!HH', qtype, 1)

    answers = b''
    if qname in dns_records:
        records = dns_records[qname]
        if qtype == DNS_TYPE_A and 'A' in records:
            for ip in records['A']:
                answer = encoded_qname + struct.pack('!HHIH', DNS_TYPE_A, 1, 300, 4)
                answer += socket.inet_aton(ip)
                answers += answer
        elif qtype == DNS_TYPE_NS and 'NS' in records:
            for ns in records['NS']:
                encoded_ns = b''
                for part in ns.split('.'):
                    encoded_ns += struct.pack('!B', len(part)) + part.encode('ascii')
                encoded_ns += b'\x00'
                answer = encoded_qname + struct.pack('!HHIH', DNS_TYPE_NS, 1, 300, len(encoded_ns))
                answer += encoded_ns
                answers += answer

    return header + question + answers

def start_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 54))
    print("DNS服务器已启动，等待查询...")

    while True:
        try:
            data, addr = server_socket.recvfrom(512)
            query_id = struct.unpack('!H', data[:2])[0]
            qname = ''
            offset = 12
            while data[offset] != 0:
                length = data[offset]
                qname += data[offset+1:offset+1+length].decode('ascii') + '.'
                offset += 1 + length
            qname = qname[:-1]
            qtype = struct.unpack('!H', data[offset+1:offset+3])[0]

            print(f"收到查询: {qname}, 类型: {qtype}")
            response = build_dns_response(query_id, qname, qtype)
            server_socket.sendto(response, addr)
        except Exception as e:
            print(f"错误: {e}")

if __name__ == '__main__':
    start_dns_server()