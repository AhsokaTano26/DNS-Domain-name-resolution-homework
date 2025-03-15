import socket
import struct
import random

# DNS记录类型
DNS_TYPE_A = 1
DNS_TYPE_NS = 2

def dns_query(qname, qtype, server_ip):
    query_id = random.randint(0, 65535)
    header = struct.pack('!HHHHHH', query_id, 0x0000, 1, 0, 0, 0)
    encoded_qname = b''
    for part in qname.split('.'):
        encoded_qname += struct.pack('!B', len(part)) + part.encode('ascii')
    encoded_qname += b'\x00'
    question = encoded_qname + struct.pack('!HH', qtype, 1)
    message = header + question

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        try:
            sock.sendto(message, (server_ip, 53))
            data, _ = sock.recvfrom(1024)
        except socket.timeout:
            return None
    return data

def parse_name(data, offset):
    parts = []
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset+1]
            offset += 2
            name, _ = parse_name(data, ptr)
            parts.append(name)
            break
        elif length == 0:
            offset += 1
            break
        else:
            start = offset + 1
            end = start + length
            if end > len(data):
                break
            parts.append(data[start:end].decode('ascii', 'replace'))
            offset = end
    return '.'.join(parts), offset

def parse_record(data, offset):
    name, offset = parse_name(data, offset)
    type_, = struct.unpack_from('!H', data, offset)
    offset += 2
    class_, = struct.unpack_from('!H', data, offset)
    offset += 2
    ttl, = struct.unpack_from('!I', data, offset)
    offset += 4
    data_len, = struct.unpack_from('!H', data, offset)
    offset += 2
    record_data = data[offset:offset+data_len]
    offset += data_len

    if type_ == DNS_TYPE_A:  # A记录
        ip = socket.inet_ntoa(record_data)
        return {'name': name, 'type': type_, 'data': ip}, offset
    elif type_ == DNS_TYPE_NS:  # NS记录
        ns_name, _ = parse_name(data, offset - data_len)
        return {'name': name, 'type': type_, 'data': ns_name}, offset
    else:
        return {'name': name, 'type': type_, 'data': record_data}, offset

def parse_response(data):
    if not data:
        return None
    try:
        header = data[:12]
        id_, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', header)
        offset = 12
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                offset += 1
            offset += 5
        answers = []
        for _ in range(ancount):
            record, offset = parse_record(data, offset)
            answers.append(record)
        authorities = []
        for _ in range(nscount):
            record, offset = parse_record(data, offset)
            authorities.append(record)
        additionals = []
        for _ in range(arcount):
            record, offset = parse_record(data, offset)
            additionals.append(record)
        return {
            'answers': answers,
            'authorities': authorities,
            'additionals': additionals
        }
    except Exception as e:
        print(f"解析响应失败: {e}")
        return None

def iterative_resolve(qname, qtype, server_ip):
    while True:
        response = dns_query(qname, qtype, server_ip)
        parsed = parse_response(response)
        if not parsed:
            return None
        if parsed['answers']:
            return [ans['data'] for ans in parsed['answers'] if ans['type'] == qtype]
        ns_records = [auth for auth in parsed['authorities'] if auth['type'] == DNS_TYPE_NS]
        if not ns_records:
            return None
        next_ns = None
        for ns in ns_records:
            ns_name = ns['data']
            a_records = [add['data'] for add in parsed['additionals'] if add['type'] == DNS_TYPE_A and add['name'] == ns_name]
            if a_records:
                next_ns = a_records[0]
                break
        if not next_ns:
            ns_name = ns_records[0]['data']
            next_ns = iterative_resolve(ns_name, DNS_TYPE_A, server_ip)
            if not next_ns:
                return None
        server_ip = next_ns[0]

# 示例使用
if __name__ == '__main__':
    qname = 'example.com'
    qtype = DNS_TYPE_A
    server_ip = '127.0.0.1'  # 本地DNS服务器
    result = iterative_resolve(qname, qtype, server_ip)
    print(f"{qname} 的A记录: {result}")