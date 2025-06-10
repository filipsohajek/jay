#pragma once
#include "jay/buf/struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"

namespace jay::ip {

struct NDPSourceAddrOption : public BufStruct<NDPSourceAddrOption, ICMPHeaderError> {
  using BufStruct::BufStruct;
  static const uint8_t UNION_TAG = 1;

  STRUCT_FIELD(addr, 0, HWAddr);

  size_t size() const {
    return sizeof(HWAddr);
  }

  static size_t size_hint() {
    return sizeof(HWAddr);
  }

  friend std::ostream &operator<<(std::ostream &os, const NDPSourceAddrOption &msg) {
    os << "source_addr=" << HWAddr(msg.addr()); 
    return os;
  }
};

struct NDPTargetAddrOption : public BufStruct<NDPTargetAddrOption, ICMPHeaderError> {
  using BufStruct::BufStruct;
  static const uint8_t UNION_TAG = 2;

  STRUCT_FIELD(addr, 0, HWAddr);

  size_t size() const {
    return sizeof(HWAddr);
  }

  static size_t size_hint() {
    return sizeof(HWAddr);
  }

  friend std::ostream &operator<<(std::ostream &os, const NDPTargetAddrOption &msg) {
    os << "target_addr=" << HWAddr(msg.addr()); 
    return os;
  }
};

struct NDPPrefixInfoOption : public BufStruct<NDPPrefixInfoOption, ICMPHeaderError> {
  using BufStruct::BufStruct;
  static const uint8_t UNION_TAG = 3;

  STRUCT_FIELD(prefix_len, 0, uint8_t);
  STRUCT_BITFIELD(on_link, 8, 1, bool);
  STRUCT_BITFIELD(autonomous, 9, 1, bool);
  STRUCT_FIELD(valid_lifetime, 2, uint32_t);
  STRUCT_FIELD(preferred_lifetime, 6, uint32_t);
  STRUCT_FIELD(prefix, 14, IPAddr);

  size_t size() const {
    return 30;
  }

  static size_t size_hint() {
    return 30; 
  }

  friend std::ostream &operator<<(std::ostream &os, const NDPPrefixInfoOption &msg) {
    os << "prefix_len=" << uint32_t(uint8_t(msg.prefix_len())) << ", "; 
    os << "on_link=" << bool(msg.on_link()) << ", "; 
    os << "autonomous=" << bool(msg.autonomous()) << ", "; 
    os << "valid_lifetime=" << uint32_t(msg.valid_lifetime()) << ", "; 
    os << "preferred_lifetime=" << uint32_t(msg.preferred_lifetime()) << ", "; 
    os << "prefix=" << IPAddr(msg.prefix());
    return os;
  }
};

struct NDPMTUOption : public BufStruct<NDPMTUOption, ICMPHeaderError> {
  using BufStruct::BufStruct;
  static const uint8_t UNION_TAG = 5;

  STRUCT_FIELD(mtu, 2, uint32_t);

  size_t size() const {
    return 6;
  }

  static size_t size_hint() {
    return 6;
  }

  friend std::ostream &operator<<(std::ostream &os, const NDPMTUOption &msg) {
    os << "mtu=" << uint32_t(msg.mtu()); 
    return os;
  }
};

struct NDPOption : public BufStruct<NDPOption, ICMPHeaderError> {
  using BufStruct::BufStruct;
  
  STRUCT_FIELD(type, 0, uint8_t);
  STRUCT_FIELD(length, 1, uint8_t);
  STRUCT_TAGGED_UNION(data, 2, type(), NDPSourceAddrOption, NDPTargetAddrOption, NDPPrefixInfoOption, NDPMTUOption);
  
  size_t size() const {
    return 2 + data().size();
  }

  template<typename TOpt>
  static Result<NDPOption, ICMPHeaderError> construct(StructWriter cur, TOpt* opt = nullptr) {
    size_t size = size_hint(opt);
    if (cur.size() < size)
      return ResultError(ICMPHeaderError::OUT_OF_BOUNDS);
    NDPOption strct {cur};
    strct.length() = size / 8;
    TOpt new_opt = strct.data().set<TOpt>().value();

    if (opt)
      *opt = new_opt;
    return strct;
  }

  template<typename TOpt>
  static size_t size_hint(TOpt*) {
    return TOpt::size_hint() + 2;
  }

  static size_t size_hint() {
    return 2;
  }

  friend std::ostream &operator<<(std::ostream &os, const NDPOption &msg) {
    os << "[type=" << uint16_t(uint8_t(msg.type())) << ", length=" << uint16_t(uint8_t(msg.length())) << ", data: ";
    std::visit([&](auto data) { 
      if constexpr (!std::is_same_v<decltype(data), std::monostate>)
        os << data; 
    }, msg.data().variant());
    os << "]";
    return os;
  }
};

struct NDPRouterSolicitation : public BufStruct<NDPRouterSolicitation, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 255;
  constexpr static const uint8_t V6_TYPE = 133;

  NDPRouterSolicitation() : BufStruct<NDPRouterSolicitation, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_VARARRAY(options, 4, NDPOption);

  friend std::ostream &operator<<(std::ostream &os, const NDPRouterSolicitation &msg) {
    os << "NDP router solicitation: options=";
    for (auto it = msg.options().begin(); it != msg.options().end(); it++) {
      os << (*it).read().value() << ", ";
    }
    return os;
  }

  static Result<NDPRouterSolicitation, ICMPHeaderError> construct(StructWriter cur, std::optional<HWAddr> source_haddr) {
    size_t size = size_hint(source_haddr);
    if (size > cur.size())
      return ResultError(ICMPHeaderError::OUT_OF_BOUNDS);
    auto msg = NDPRouterSolicitation {cur.slice(0, size)};

    if (source_haddr.has_value()) {
      NDPSourceAddrOption saddr_opt;
      (*msg.options().begin()).construct(&saddr_opt);
      saddr_opt.addr() = source_haddr.value();
    }

    return msg;
  }

  static size_t size_hint(std::optional<HWAddr> source_haddr) {
    return 4 + (source_haddr.has_value() ? NDPOption::size_hint<NDPSourceAddrOption>(nullptr) : 0);
  }

  static size_t size_hint() {
    return 4;
  }

  size_t size() const { return options().size(); }
};

struct NDPRouterAdvertisement : public BufStruct<NDPRouterAdvertisement, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 255;
  constexpr static const uint8_t V6_TYPE = 134;

  NDPRouterAdvertisement() : BufStruct<NDPRouterAdvertisement, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_FIELD(hop_limit, 0, uint8_t);
  STRUCT_BITFIELD(managed, 8, 1, bool);
  STRUCT_BITFIELD(other_conf, 9, 1, bool);
  STRUCT_FIELD(router_lifetime, 2, uint16_t);
  STRUCT_FIELD(reachable_time, 4, uint32_t);
  STRUCT_FIELD(retrans_timer, 8, uint32_t);
  STRUCT_VARARRAY(options, 12, NDPOption);

  friend std::ostream &operator<<(std::ostream &os, const NDPRouterAdvertisement &msg) {
    os << "NDP router advertisement: options=";
    for (auto it = msg.options().begin(); it != msg.options().end(); it++) {
      os << (*it).read().value() << ", ";
    }
    return os;
  }

  size_t size() const { 
    return 12 + options().size(); 
  }

  static size_t size_hint() {
    return 12;
  }
};

struct NDPNeighborSolicitation : public BufStruct<NDPNeighborSolicitation, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 255;
  constexpr static const uint8_t V6_TYPE = 135;

  NDPNeighborSolicitation() : BufStruct<NDPNeighborSolicitation, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_FIELD(target_addr, 4, IPAddr);
  STRUCT_VARARRAY(options, 20, NDPOption);

  friend std::ostream &operator<<(std::ostream &os, const NDPNeighborSolicitation &msg) {
    os << "NDP neighbor solicitation: options=";
    for (auto it = msg.options().begin(); it != msg.options().end(); it++) {
      os << (*it).read().value() << ", ";
    }
    return os;
  }

  static Result<NDPNeighborSolicitation, ICMPHeaderError> construct(StructWriter cur, std::optional<HWAddr> source_haddr) {
    size_t size = size_hint(source_haddr);
    if (size > cur.size())
      return ResultError(ICMPHeaderError::OUT_OF_BOUNDS);
    auto msg = NDPNeighborSolicitation {cur.slice(0, size)};

    if (source_haddr.has_value()) {
      NDPSourceAddrOption saddr_opt;
      (*msg.options().begin()).construct(&saddr_opt);
      saddr_opt.addr() = source_haddr.value();
    }

    return msg;
  }

  static size_t size_hint(std::optional<HWAddr> source_haddr) {
    return 20 + (source_haddr.has_value() ? NDPOption::size_hint<NDPSourceAddrOption>(nullptr) : 0);
  }

  static size_t size_hint() {
    return 20;
  }

  size_t size() const { return 20 + options().size(); }
};

struct NDPNeighborAdvertisement : public BufStruct<NDPNeighborAdvertisement, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 255;
  constexpr static const uint8_t V6_TYPE = 136;

  NDPNeighborAdvertisement() : BufStruct<NDPNeighborAdvertisement, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_BITFIELD(router, 0, 1, bool);
  STRUCT_BITFIELD(solicited, 1, 1, bool);
  STRUCT_BITFIELD(override, 2, 1, bool);
  STRUCT_FIELD(target_addr, 4, IPAddr);
  STRUCT_VARARRAY(options, 20, NDPOption);

  friend std::ostream &operator<<(std::ostream &os, const NDPNeighborAdvertisement &msg) {
    os << "NDP neighbor advertisement: options=";
    for (auto it = msg.options().begin(); it != msg.options().end(); it++) {
      os << (*it).read().value() << ", ";
    }
    return os;
  }

  static Result<NDPNeighborAdvertisement, ICMPHeaderError> construct(StructWriter cur, std::optional<HWAddr> target_haddr) {
    size_t size = size_hint(target_haddr);
    if (size > cur.size())
      return ResultError(ICMPHeaderError::OUT_OF_BOUNDS);
    auto msg = NDPNeighborAdvertisement {cur.slice(0, size)};

    if (target_haddr.has_value()) {
      NDPTargetAddrOption taddr_opt;
      (*msg.options().begin()).construct(&taddr_opt);
      taddr_opt.addr() = target_haddr.value();
    }

    return msg;
  }

  static size_t size_hint(std::optional<HWAddr> target_haddr) {
    return 20 + (target_haddr.has_value() ? NDPOption::size_hint<NDPTargetAddrOption>(nullptr) : 0);
  }

  static size_t size_hint() {
    return 20;
  }

  size_t size() const { return 20 + options().size(); }
};
}
