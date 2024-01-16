import select
import socket
import threading
import time
from collections import defaultdict
from dnslib import DNSRecord, DNSHeader, DNSQuestion


def print_log(message):
    print(
        f"{time.strftime('%Y-%m-%d %H:%M:%S')} - dns_server - INFO - {message}")


class DnsServer:
    def __init__(self, host='127.0.0.1', port=53):
        self.host = host
        self.port = port
        self.udp_socket = None
        self.tcp_socket = None

        self.dns_cache = defaultdict(lambda: {"timestamp": 0, "records": []})
        self.setup_sockets()

    def setup_sockets(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.host, self.port))

        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.bind((self.host, self.port))
        self.tcp_socket.listen(5)

    def resolve_recursive(self, question, root_dns_server=('198.41.0.4', 53)):
        current_qname, current_qtype = question.qname, question.qtype
        cache_key = (current_qname, current_qtype)

        if (cache_key in self.dns_cache and
                time.time() - self.dns_cache[cache_key]["timestamp"] < min(
                    ttl for _, ttl in self.dns_cache[cache_key]["records"])):
            print_log(f"Answer found in cache for {current_qname}")
            return self.dns_cache[cache_key]["records"]

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
            dns_socket.settimeout(5)
            dns_socket.sendto(
                DNSRecord(q=DNSQuestion(current_qname, current_qtype)).pack(),
                root_dns_server)

            try:
                data, _ = dns_socket.recvfrom(1024)
                response = DNSRecord.parse(data)

                if response.rr:
                    print_log(
                        f"Answer found in the response: {response.rr[0].rdata}")
                    self.dns_cache[cache_key]["timestamp"] = time.time()
                    self.dns_cache[cache_key]["records"] = [(rr, rr.ttl) for rr
                                                            in response.rr]
                    return self.dns_cache[cache_key]["records"]

                for rrset in response.ar:
                    if rrset.rtype == 1:
                        return self.resolve_recursive(question,
                                                      (str(rrset.rdata), 53))
            except socket.timeout:
                pass

        return None

    def handle_dns_request(self, data):
        try:
            request = DNSRecord.parse(data)
            question = request.questions[0]

            print_log(f"Incoming DNS request: {question}")
            answer = self.resolve_recursive(question)
            response = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

            if answer:
                for rr, ttl in answer:
                    response.add_answer(rr)
                    rr.ttl = ttl

            print_log(f"DNS response: {response.rr}")
            return response.pack()

        except Exception as e:
            print_log(f"Error processing DNS request: {e}")
            return None

    def handle_client(self, client_socket):
        data = client_socket.recv(1024)
        response_data = self.handle_dns_request(data)

        if response_data:
            client_socket.send(response_data)

        client_socket.close()

    def run(self):
        print_log(f"DNS server listening on {self.host}:{self.port}")

        while True:
            try:
                readable, _, _ = select.select(
                    [self.udp_socket, self.tcp_socket], [], [], 5)
                for s in readable:
                    if s is self.udp_socket:
                        data, addr = self.udp_socket.recvfrom(1024)
                        response_data = self.handle_dns_request(data)

                        if response_data:
                            self.udp_socket.sendto(response_data, addr)
                    elif s is self.tcp_socket:
                        client_socket, _ = self.tcp_socket.accept()
                        threading.Thread(target=self.handle_client,
                                         args=(client_socket,)).start()
            except KeyboardInterrupt:
                break

        self.udp_socket.close()
        self.tcp_socket.close()


if __name__ == "__main__":
    dns_server = DnsServer()
    dns_server.run()
