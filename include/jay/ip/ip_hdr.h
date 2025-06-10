#pragma once

#include "jay/buf/variant_struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"
#include "jay/ip/v4.h"
#include "jay/ip/v6.h"
namespace jay::ip {
/// Deserialized IP (v4/v6) header.
struct IPHeader : public std::variant<IPv4Header, IPv6Header>, JointStruct {
  using std::variant<IPv4Header, IPv6Header>::variant;
  using ErrorType = IPHeaderError;

  JOINT_FIELD(version, IPVersion);
  JOINT_FIELD(src_addr, IPAddr);
  JOINT_FIELD(dst_addr, IPAddr);
  JOINT_FIELD(ttl, uint8_t);

  size_t size() const {
    return std::visit([](const auto &hdr) { return hdr.size(); }, *this);
  }

  bool is_v4() const {
    return std::holds_alternative<IPv4Header>(*this);
  }

  bool is_v6() const {
    return std::holds_alternative<IPv6Header>(*this);
  }

  IPv4Header& v4() {
    return std::get<IPv4Header>(*this);
  }
  IPv6Header& v6() {
    return std::get<IPv6Header>(*this);
  }

  size_t upper_layer_size() {
    if (is_v4()) {
      return v4().total_len() - v4().size();
    } else {
      return v6().payload_len() - v6().exthdr_size();
    }
  }

  uint32_t pseudohdr_sum(IPProto protocol) {
    return IPAddr(src_addr()).be_sum() + IPAddr(dst_addr()).be_sum() + __bswap_16(static_cast<uint16_t>(upper_layer_size())) + static_cast<uint8_t>(protocol);
  }

  static Result<IPHeader, IPHeaderError> read(StructWriter cur, IPVersion ver) {
    switch (ver) {
      case IPVersion::V4:
        return IPv4Header::read(cur);
      case IPVersion::V6:
        return IPv6Header::read(cur);
    }
  }

  template<typename... CArgT>
  static Result<IPHeader, IPHeaderError> construct(StructWriter cur, IPVersion ver, CArgT&& ...args) {
    switch (ver) {
      case IPVersion::V4:
        return IPv4Header::construct(cur, std::forward<CArgT>(args)...);
      case IPVersion::V6:
        return IPv6Header::construct(cur, std::forward<CArgT>(args)...);
    }
  }

  template<typename... CArgT>
  static Result<size_t, IPHeaderError> size_hint(IPVersion ver, CArgT&& ...args) {
    switch (ver) {
      case IPVersion::V4:
        return IPv4Header::size_hint(std::forward<CArgT>(args)...);
      case IPVersion::V6:
        return IPv6Header::size_hint(std::forward<CArgT>(args)...);
    }
  }

  friend std::ostream &operator<<(std::ostream &os, const IPHeader &addr) {
    os << "IP [" << IPAddr(addr.src_addr()) << " -> " << IPAddr(addr.dst_addr()) << "]: ttl=" << uint32_t(uint8_t(addr.ttl()));
    return os;
  }
};


}
