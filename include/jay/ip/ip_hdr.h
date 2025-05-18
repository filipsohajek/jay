#pragma once

#include "jay/buf/variant_struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"
#include "jay/ip/v4.h"
namespace jay::ip {
/// Deserialized IP (v4/v6) header.
struct IPHeader : public std::variant<IPv4Header>, JointStruct {
  using std::variant<IPv4Header>::variant;
  using ErrorType = IPHeaderError;

  JOINT_FIELD(version, IPVersion);
  JOINT_FIELD(src_addr, IPAddr);
  JOINT_FIELD(dst_addr, IPAddr);
  JOINT_FIELD(ttl, uint8_t);
  JOINT_FIELD(proto, IPProto);

  void copy_to(IPHeader dest) const {
    if (std::holds_alternative<IPv4Header>(*this)) {
      std::get<IPv4Header>(*this).copy_to(std::get<IPv4Header>(dest));
    }
  }

  size_t size() const {
    return std::visit([](const auto &hdr) { return hdr.size(); }, *this);
  }

  bool is_v4() const {
    return std::holds_alternative<IPv4Header>(*this);
  }

  IPv4Header& v4() {
    return std::get<IPv4Header>(*this);
  }

  static Result<IPHeader, IPHeaderError> read(StructWriter cur, IPVersion ver) {
    switch (ver) {
      case IPVersion::V4:
        return IPv4Header::read(cur);
    }
  }

  template<typename... CArgT>
  static Result<IPHeader, IPHeaderError> construct(StructWriter cur, IPVersion ver, CArgT&& ...args) {
    switch (ver) {
      case IPVersion::V4:
        return IPv4Header::construct(cur, std::forward<CArgT>(args)...);
    }
  }

  template<typename... CArgT>
  static Result<size_t, IPHeaderError> size_hint(IPVersion ver, CArgT&& ...args) {
    switch (ver) {
      case IPVersion::V4:
        return IPv4Header::size_hint(std::forward<CArgT>(args)...);
    }
  }

  uint32_t pseudohdr_sum() const {
    return std::visit([](const auto &hdr) { return hdr.pseudohdr_sum(); }, *this);
  }

  friend std::ostream &operator<<(std::ostream &os, const IPHeader &addr) {
    os << "IP [" << IPAddr(addr.src_addr()) << " -> " << IPAddr(addr.dst_addr()) << "]: ttl=" << uint32_t(uint8_t(addr.ttl())) << ", proto=" << uint16_t(IPProto(addr.proto()));
    return os;
  }
};


}
