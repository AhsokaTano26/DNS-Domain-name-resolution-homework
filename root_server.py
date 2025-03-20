import socket
import struct

def load_records(file_path):
    records = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            parts = line.split(',')
            if len(parts) != 3:
                continue
            name, record_type, data = parts
            key = (name.strip(), record_type.strip())
            if key not in records:
                records[key] = []
            records[key].append(data.strip())
    return records

root_records = load_records('root_dns_records.txt')

def build_response(query_id, qname, qtype):
    header = struct.pack('!HHHHHH', query_id, 0x8180, 1, 0, 0, 0)
    encoded_qname = b''
    for part in qname.split('.'):
        encoded_qname += struct.pack('!B', len(part)) + part.encode('ascii')
    encoded_qname += b'\x00'
    question = encoded_qname + struct.pack('!HH', 2 if qtype == 'NS' else 1, 1)  # 假设qtype为NS或A

    answers = b''
    key = (qname, 'NS')
    if key in root_records:
        for ns in root_records[key]:
            encoded_ns = b''
            for part in ns.split('.'):
                encoded_ns += struct.pack('!B', len(part)) + part.encode('ascii')
            encoded_ns += b'\x00'
            answer = encoded_qname + struct.pack('!HHIH', 2, 1, 300, len(encoded_ns))
            answer += encoded_ns
            answers += answer

    return header + question + answers

def start_root_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('0.0.0.0', 5353))  # 根服务器监听5353端口
    print("根DNS服务器已启动 (端口:5353)...")

    while True:
        data, addr = server.recvfrom(512)
        query_id = struct.unpack('!H', data[:2])[0]
        qname = ''
        offset = 12
        while data[offset] != 0:
            length = data[offset]
            qname += data[offset+1:offset+1+length].decode('ascii') + '.'
            offset += 1 + length
        qname = qname.rstrip('.')
        response = build_response(query_id, qname, 'NS')
        server.sendto(response, addr)

if __name__ == '__main__':
    start_root_server()