import socket

def dns_query(domain, query_type='A'):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(f"{domain},{query_type}".encode(), ('127.0.0.1', 10003))
        data, _ = s.recvfrom(1024)
        return data.decode().split('\n')

if __name__ == '__main__':
    while True:
        domain = input("请输入要查询的域名 (q退出): ")
        if domain.lower() == 'q':
            break
        query_type = input("请输入记录类型 (A/MX/NS): ").upper()
        results = dns_query(domain, query_type)
        print("查询结果:")
        for res in results:
            print(res)