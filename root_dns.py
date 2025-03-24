import socket
import sys


def load_records(filename):
    records = {}
    with open(filename, 'r',encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 4:
                domain = parts[0]
                type_ = parts[1]
                value = ' '.join(parts[2:])
                if domain not in records:
                    records[domain] = []
                records[domain].append((type_, value))
    return records


def main():
    records = load_records('records/root.txt')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', 10000)
    sock.bind(server_address)
    while True:
        data, address = sock.recvfrom(4096)
        domain, query_type = data.decode().split(',')
        print(f"Root Server收到查询: {domain} {query_type}")

        response = []
        search_domains = [domain]

        print(f"[{server_address}] 收到查询: {domain} ({query_type}) 来自 {address}")
        print(f"搜索路径: {search_domains}")
        print(f"返回记录: {response}")

        # 支持多级域名查找（如将 www.example.com 拆分为 example.com）
        parts = domain.split('.')
        while len(parts) > 1:
            parts = parts[1:]
            search_domains.append('.'.join(parts))

        for search_domain in search_domains:
            if search_domain in records:
                for type_, value in records[search_domain]:
                    if type_ == query_type or query_type == 'ANY':
                        response.append(f"{search_domain} {type_} {value}")
                break  # 找到最接近的上级域
        if domain in records:
            for type_, value in records[domain]:
                if type_ == query_type or query_type == 'ANY':
                    response.append(f"{domain} {type_} {value}")

        if not response:
            response = ["未找到记录"]

        sock.sendto('\n'.join(response).encode(), address)



if __name__ == '__main__':
    main()