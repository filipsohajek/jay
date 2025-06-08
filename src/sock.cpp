#include "jay/ip/sock.h"
#include "jay/ip/stack.h"

namespace jay::ip {
void Socket::send_pbuf(PBuf packet, std::optional<IPAddr> dst_ip) {
  if ((dst_ip == std::nullopt)) {
    if (!_remote_addr.has_value())
      throw std::runtime_error("send called on a socket with no remote address");
    dst_ip = _remote_addr;
  }
  IPAddr ip = dst_ip.value();

  auto ip_hdr = packet->construct_net_hdr<IPHeader>(ip.version()).value();
  ip_hdr.proto() = _protocol;
  ip_hdr.dst_addr() = ip;
  if (_local_addr.has_value()) {
    ip_hdr.src_addr() = _local_addr.value();
  }
  ip_stack.output(std::move(packet));
}

void Socket::listen(std::optional<IPAddr> local_addr, uint16_t local_port) {
  ip_stack.sock_table().listen(this, local_addr, local_port);
}

void Socket::connect(IPAddr remote_addr, uint16_t remote_port, std::optional<IPAddr> local_addr, uint16_t local_port) {
  ip_stack.sock_table().connect(this, remote_addr, remote_port, local_addr, local_port);
}

Socket::~Socket() {
  ip_stack.sock_table().remove(this);
}
};
