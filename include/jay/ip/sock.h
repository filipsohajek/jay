#pragma once

#include "jay/pbuf.h"
namespace jay::ip {
class IPStack;
class IPSocket {
  friend class IPStack;
public:
  IPSocket(const IPSocket&) = delete;
  IPSocket(IPSocket&&) = delete;
  IPSocket& operator=(const IPSocket&) = delete;
  IPSocket& operator=(IPSocket&&) = delete;

  std::optional<IPAddr> local_addr() const {
    return _local_addr;
  }

  std::optional<IPAddr> remote_addr() const {
    return _remote_addr;
  }
protected:
  IPSocket(IPStack& ip_stack) : ip_stack(ip_stack) {}
  void send_pbuf(PBuf, std::optional<IPAddr> = std::nullopt);

  IPStack& ip_stack;
  IPProto protocol;
  std::optional<IPAddr> _local_addr, _remote_addr;
};
};
