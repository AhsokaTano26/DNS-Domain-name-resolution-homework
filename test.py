import socket
import struct
import random

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
    max_jumps = 5
    jumps = 0
    while jumps < max_jumps:
        if offset >= len(data):
            break
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset+1]
            offset += 2
            jumps += 1
            offset = ptr
            continue
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
        jumps += 1
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

    if type_ == 1:  # A记录
        ip = socket.inet_ntoa(record_data)
        return {'name': name, 'type': type_, 'data': ip}, offset
    elif type_ == 2:  # NS记录
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
    except:
        return None

def resolve_ns(ns_name, root_server):
    response = dns_query(ns_name, 1, root_server)
    parsed = parse_response(response)
    if parsed and parsed['answers']:
        return parsed['answers'][0]['data']
    authorities = parsed['authorities'] if parsed else []
    ns_list = [auth['data'] for auth in authorities if auth['type'] == 2]
    if ns_list:
        next_ns = ns_list[0]
        return resolve_ns(next_ns, root_server)
    return None

def iterative_resolve(qname, qtype):
    root_servers = ['198.41.0.4']
    current_server = root_servers[0]
    while True:
        response = dns_query(qname, qtype, current_server)
        parsed = parse_response(response)
        if not parsed:
            return None
        if parsed['answers']:
            return [ans['data'] for ans in parsed['answers'] if ans['type'] == qtype]
        ns_records = [auth for auth in parsed['authorities'] if auth['type'] == 2]
        if not ns_records:
            return None
        next_ns = None
        for ns in ns_records:
            ns_name = ns['data']
            a_records = [add['data'] for add in parsed['additionals'] if add['type'] == 1 and add['name'] == ns_name]
            if a_records:
                next_ns = a_records[0]
                break
        if not next_ns:
            ns_name = ns_records[0]['data']
            next_ns = resolve_ns(ns_name, root_servers[0])
            if not next_ns:
                return None
        current_server = next_ns

# 示例使用
if __name__ == '__main__':
    result = iterative_resolve('example.com', 1)
    print("A记录结果:", result)