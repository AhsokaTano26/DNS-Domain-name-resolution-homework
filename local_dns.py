import socket


class LocalDNS:
    def __init__(self):
        self.cache = {}
        self.root_servers = [('127.0.0.1', 10000)]

    # local_dns.py 修改后核心逻辑
    def iterative_query(self, domain, query_type):
        current_servers = self.root_servers.copy()
        query_path = []  # 跟踪查询路径
        max_depth = 5  # 适当增加深度限制

        for _ in range(max_depth):
            print(f"当前查询服务器: {current_servers}")
            next_servers = []

            for server in current_servers:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(2)
                        query_msg = f"{domain},{query_type}"
                        s.sendto(query_msg.encode(), server)
                        data, _ = s.recvfrom(1024)
                        response = data.decode().split('\n')

                        # 解析响应
                        auth_servers = []
                        final_answer = []

                        for record in response:
                            if not record or "未找到" in record:
                                continue

                            parts = record.strip().split()
                            if len(parts) < 3:
                                continue

                            # 记录类型处理
                            if parts[1] == 'NS':
                                ns_addr = parts[2].split(':')
                                auth_servers.append((ns_addr[0], int(ns_addr[1])))
                            elif parts[1] in ['A', 'MX']:
                                final_answer.append(record)

                        # 发现最终答案
                        if final_answer:
                            print(f"查询路径: {' -> '.join(query_path)} -> {server}")
                            return final_answer

                        # 更新下一跳服务器
                        if auth_servers:
                            current_servers = auth_servers
                            query_path.append(f"{server} (NS)")
                            break

                except socket.timeout:
                    print(f"超时: {server}")
                    continue
                except Exception as e:
                    print(f"连接错误: {server} - {str(e)}")
                    continue

            # 检查是否所有服务器都无响应
            if not next_servers:
                break

        return ["Error: 查询失败（可能原因：1.域名不存在 2.DNS记录链不完整 3.服务器未响应）"]

    def handle_query(self, data):
        domain, query_type = data.decode().split(',')
        print(f"本地DNS收到查询: {domain} {query_type}")

        # 检查缓存
        if domain in self.cache:
            return self.cache[domain]

        # 发起迭代查询
        result = self.iterative_query(domain, query_type)
        self.cache[domain] = result
        return result


def main():
    dns = LocalDNS()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 10003))

    while True:
        data, addr = sock.recvfrom(1024)
        response = dns.handle_query(data)
        sock.sendto('\n'.join(response).encode(), addr)


if __name__ == '__main__':
    main()