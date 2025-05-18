#pragma once
#include <functional>
#include <stdexcept>
#include "jay/ip/sock.h"
namespace jay::udp {
class UDPSocket : public ip::IPSocket {
  friend class UDPStack;
public:
  virtual ~UDPSocket();

  void send(const Buf& buf, std::optional<ip::IPAddr> dst_ip = std::nullopt, uint16_t dst_port = 0) {
    send_pbuf(PBuf(buf, true), dst_ip, dst_port);
  }

  std::function<void(UDPSocket&, const Buf&, ip::IPAddr, uint16_t)> on_data_fn;
protected:
  UDPSocket(ip::IPStack& ip_stack) : IPSocket(ip_stack) {};

  void send_pbuf(PBuf packet, std::optional<ip::IPAddr> dst_ip = std::nullopt, uint16_t dst_port = 0) {
    auto udp_hdr = packet->construct_tspt_hdr<UDPHeader>().value();

    if (dst_port == 0) {
      if (_remote_port == 0)
        throw std::invalid_argument("send called on an UDP socket with no remote port");
      dst_port = _remote_port;
    }

    udp_hdr.src_port() = _local_port;
    udp_hdr.dst_port() = dst_port;
    packet->unmask(udp_hdr.size());
    udp_hdr.length() = packet->size();

    ip::IPSocket::send_pbuf(std::move(packet), dst_ip);
  }

  void deliver(const PBuf& packet) {
     if (on_data_fn)
      on_data_fn(*this, packet->buf(), packet->ip().src_addr(), packet->udp().src_port());
  }

  uint16_t local_port() const {
    return _local_port;
  }

  uint16_t remote_port() const {
    return _remote_port;
  }

  uint16_t _local_port, _remote_port;
};
}
