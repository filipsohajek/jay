#pragma once
#include "jay/buf/sbuf.h"
#include "jay/buf/struct.h"
#include "jay/ip/arp.h"
#include "jay/ip/icmp_hdr.h"
#include "jay/ip/igmp.h"
#include "jay/ip/ip_hdr.h"
#include "jay/ip/v4.h"
#include "jay/udp/udp_hdr.h"
#include <cassert>
#include <endian.h>
#include <variant>

namespace jay {
struct NoHdr : public std::monostate, public BufStruct<NoHdr> {
  using BufStruct::BufStruct;
  NoHdr() : BufStruct<NoHdr>(StructWriter({})) {}
  size_t size() const { return 0; }
  friend std::ostream &operator<<(std::ostream &os, const NoHdr &) {
    os << "no header";
    return os;
  }
};

#define _CONSTRUCT_HDR_FN(name)  template<typename THdr, typename ...CArgT>\
  requires IsVariantAlternative<THdr, decltype(name)>::value\
  Result<THdr, typename THdr::ErrorType> construct_ ## name (CArgT&& ...constr_args) {\
    Result<size_t, typename THdr::ErrorType> size_hint = THdr::size_hint(std::forward<CArgT>(constr_args)...);\
    if (size_hint.has_error())\
      return ResultError(size_hint.error());\
    unmask(size_hint.value());\
    StructWriter writer(begin().contiguous().subspan(0, size_hint.value()));\
    auto hdr_res = THdr::construct(writer, std::forward<CArgT>(constr_args)...);\
    mask(size_hint.value());\
    if (hdr_res.has_value())\
      name = hdr_res.value();\
    return hdr_res;\
  }

#define _READ_HDR_FN(name) template<typename THdr, typename ...RArgT>\
  requires IsVariantAlternative<THdr, decltype(name)>::value\
  Result<THdr, typename THdr::ErrorType> read_ ## name (RArgT&&... read_args) {\
    StructWriter writer(begin().contiguous());\
    Result<THdr, typename THdr::ErrorType> hdr_res = THdr::read(writer, std::forward<RArgT>(read_args)...);\
    if (hdr_res.has_value()) {\
      name = hdr_res.value();\
      mask(hdr_res.value().size());\
    }\
    return hdr_res;\
  }

class Interface;
class PBufStruct : public Buf {
public:
  using Buf::Buf;

  Interface *iface = nullptr;
  std::optional<ip::IPAddr> nh_iaddr;
  std::optional<HWAddr> nh_haddr;

  bool local = false;
  bool forwarded = false;
  
  bool has_last_fragment = false;

  std::variant<NoHdr, EthHeader> link_hdr;
  std::variant<NoHdr, ip::ARPHeader, ip::IPHeader, ip::IGMPHeader> net_hdr;
  std::variant<NoHdr, ip::ICMPHeader, udp::UDPHeader> tspt_hdr;
  
  PBufStruct(size_t payload_size) : Buf(payload_size + 128) {
    mask(128);
  }

  PBufStruct(const Buf& buf) : Buf(buf) {}
  PBufStruct(const Buf& buf, bool res_headers = false) : Buf(buf) {
    if (res_headers)
      reserve_headers();
  }

  void reserve_headers() {
    reserve_before(128);
  }

  /// Construct a link-layer header before the masked position. The resulting header is not unmasked.
  _CONSTRUCT_HDR_FN(link_hdr)
  /// Construct a network-layer header before the masked position. The resulting header is not unmasked.
  _CONSTRUCT_HDR_FN(net_hdr)
  /// Construct a transport-layer header before the masked position. The resulting header is not unmasked.
  _CONSTRUCT_HDR_FN(tspt_hdr)

  /// Read a link-layer header at the masked position. The resulting header data is masked.
  _READ_HDR_FN(link_hdr)
  /// Read a network-layer header at the masked position. The resulting header data is masked.
  _READ_HDR_FN(net_hdr)
  /// Read a transport-layer header at the masked position. The resulting header data is masked.
  _READ_HDR_FN(tspt_hdr)

  Buf& buf() {
    return *this;
  }

  Result<Buf::Iterator, Buf::InsertError> insert(PBufStruct& other, size_t offset, size_t length = std::dynamic_extent) {
    return Buf::insert(other, offset, length);
  }
  
  bool is_ip() { return std::holds_alternative<ip::IPHeader>(net_hdr); }
  bool is_arp() { return std::holds_alternative<ip::ARPHeader>(net_hdr); }
  bool is_igmp() { return std::holds_alternative<ip::IGMPHeader>(net_hdr); }
  bool is_icmp() { return std::holds_alternative<ip::ICMPHeader>(tspt_hdr); }
  bool is_udp() { return std::holds_alternative<udp::UDPHeader>(tspt_hdr); }

  EthHeader eth() { return std::get<EthHeader>(link_hdr); }
  ip::IPHeader ip() { return std::get<ip::IPHeader>(net_hdr); }
  ip::ARPHeader arp() { return std::get<ip::ARPHeader>(net_hdr); }
  ip::IGMPHeader igmp() { return std::get<ip::IGMPHeader>(net_hdr); }
  ip::ICMPHeader icmp() { return std::get<ip::ICMPHeader>(tspt_hdr); }
  udp::UDPHeader udp() { return std::get<udp::UDPHeader>(tspt_hdr); }

  friend std::ostream &operator<<(std::ostream &os, PBufStruct &addr) {
    os << "Packet (unmasked size=" << addr.size() << ")\n";
    os << "Link: ";
    std::visit([&](const auto& hdr) { os << hdr; }, addr.link_hdr);
    os << "\n";
    os << "Network: ";
    std::visit([&](const auto& hdr) { os << hdr; }, addr.net_hdr);
    os << "\n";
    os << "Transport: ";
    std::visit([&](auto& hdr) { os << hdr; }, addr.tspt_hdr);
    os << "\n";
    os << "Unmasked data: \n";
    size_t rem_line = 15;
    for (uint8_t b : addr) {
      os << std::format("{:02x} ", b);
      if (rem_line-- == 0) {
        os << "\n";
        rem_line = 15;
      }
    }
    if (rem_line != 0)
      os << "\n";
    os << "\n";
    return os;
  }
};

class PBuf : public std::unique_ptr<PBufStruct> {
  using std::unique_ptr<PBufStruct>::unique_ptr;
public:
  PBuf() : std::unique_ptr<PBufStruct>(std::make_unique<PBufStruct>()) {};
  template<typename ...T>
  PBuf(T&&... args) : std::unique_ptr<PBufStruct>(std::make_unique<PBufStruct>(std::forward<T>(args)...)) {}
  
  template<typename TMsg, typename TCode = uint8_t>
  static PBuf icmp_for(ip::IPAddr dst_addr, TMsg* msg = nullptr, TCode code = 0, Buf* payload = nullptr, std::optional<ip::IPAddr> src_addr = std::nullopt) {
    PBuf packet;
    packet->reserve_headers();
    if (payload) {
      packet->buf().insert(*payload, 0);
    }

    TMsg tmp_msg;
    auto icmp_hdr = packet->construct_tspt_hdr<ip::ICMPHeader>(dst_addr.version(), msg ? *msg : tmp_msg, code).value();
    packet->unmask(icmp_hdr.size());

    auto ip_hdr = packet->construct_net_hdr<ip::IPHeader>(dst_addr.version()).value();
    ip_hdr.proto() = ip::IPProto::ICMP;
    ip_hdr.dst_addr() = dst_addr;
    if (src_addr.has_value())
      ip_hdr.src_addr() = src_addr.value();
    
    return packet;
  }
};

} // namespace jay
