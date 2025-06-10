#pragma once

#include "jay/buf/struct.h"
#include "jay/eth.h"
#include "jay/ip/common.h"
#include <cstdint>
namespace jay::ip {
enum class ARPAddrSpace : uint16_t { ETHERNET = 1 };
enum class ARPOp : uint16_t { REQUEST = 1, REPLY = 2 };

struct ARPHeader : public BufStruct<ARPHeader> {
  using BufStruct::BufStruct;
  static const size_t SIZE = 28;

  STRUCT_FIELD(haddr_type, 0, ARPAddrSpace);
  STRUCT_FIELD(iaddr_type, 2, EtherType);
  STRUCT_FIELD(haddr_len, 4, uint8_t);
  STRUCT_FIELD(iaddr_len, 5, uint8_t);
  STRUCT_FIELD(op, 6, ARPOp);
  STRUCT_FIELD(sdr_haddr, 8, HWAddr);
  STRUCT_FIELD(sdr_iaddr, 14, IPv4Addr);
  STRUCT_FIELD(tgt_haddr, 18, HWAddr);
  STRUCT_FIELD(tgt_iaddr, 24, IPv4Addr);

  static Result<ARPHeader, BufError> construct(StructWriter cur) {
    ARPHeader hdr {cur};
    hdr.haddr_type() = ARPAddrSpace::ETHERNET;
    hdr.iaddr_type() = EtherType::IPV4;
    hdr.haddr_len() = sizeof(HWAddr);
    hdr.iaddr_len() = sizeof(IPv4Addr);
    return hdr;
  }

  size_t size() const { return SIZE; }

  static size_t size_hint() {
    return 28;
  }

  friend std::ostream &operator<<(std::ostream &os, const ARPHeader &addr) {
    os << "ARP: op=" << uint16_t(ARPOp(addr.op())) << ", sdr=(" << HWAddr(addr.sdr_haddr()) << ", " << IPv4Addr(addr.sdr_iaddr()) << "), tgt=(" << HWAddr(addr.tgt_haddr()) << ", " << IPv4Addr(addr.tgt_iaddr()) << ")";
    return os;
  }
};
}
