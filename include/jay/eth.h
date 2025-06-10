#pragma once
#include "jay/buf/struct.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <ostream>

namespace jay {
struct HWAddr : public std::array<uint8_t, 6> {
  static HWAddr zero() { return HWAddr{0}; }

  static HWAddr broadcast() {
    return HWAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  }

  friend std::ostream &operator<<(std::ostream &os, const HWAddr &addr) {
    os << std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", addr[0],
                      addr[1], addr[2], addr[3], addr[4], addr[5]);
    return os;
  }
};
enum class EtherType : uint16_t { ARP = 0x0806, IPV4 = 0x0800, IPV6 = 0x86dd};

struct EthHeader : public BufStruct<EthHeader> {
  using BufStruct<EthHeader>::BufStruct;
  static const size_t SIZE = 14;

  STRUCT_FIELD(dst_haddr, 0, HWAddr);
  STRUCT_FIELD(src_haddr, 6, HWAddr);
  STRUCT_FIELD(ether_type, 12, EtherType);
  
  size_t size() const { return SIZE; }

  static size_t size_hint() {
    return 14;
  }
  friend std::ostream &operator<<(std::ostream &os, const EthHeader &addr) {
    os << "Ethernet [" << HWAddr(addr.src_haddr()) << " -> " << HWAddr(addr.dst_haddr()) << "]: ether_type=" << uint16_t(EtherType(addr.ether_type()));
    return os;
  }
};
} // namespace jay
