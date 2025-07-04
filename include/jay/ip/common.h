#pragma once

#include "jay/buf/sbuf.h"
#include "jay/eth.h"
#include "jay/util/trie.h"
#include <array>
#include <cstdint>
#include <numeric>
#include <ostream>
#include <format>

namespace jay::ip {
inline uint16_t inet_csum(std::span<const uint8_t> data, uint32_t init_sum = 0) {
  if (data.size() > 65535)
    throw std::out_of_range(
        "internet checksum of data of size >65536 is not implemented");
  std::span<const uint16_t> words{reinterpret_cast<const uint16_t *>(data.data()),
                            data.size() / 2};
  uint32_t sum =
      std::accumulate(words.begin(), words.end(), init_sum,
                      [](uint32_t acc, uint16_t word) { return acc + uint32_t(word); });
  return ~static_cast<uint16_t>((sum & 0xffff) + (sum >> 16));
}

inline uint16_t inet_csum(Buf &buf, uint32_t init_sum = 0) {
  uint32_t sum = init_sum;
  for (auto it = buf.begin(); it != buf.end(); it = it.next_chunk()) {
    std::span<uint16_t> words{
        reinterpret_cast<uint16_t *>(it.contiguous().data()),
        it.contiguous().size() / 2};
    sum += std::accumulate(
        words.begin(), words.end(), 0,
        [](uint32_t acc, uint16_t word) { return acc + uint32_t(word); });
  }
  return ~static_cast<uint16_t>((sum & 0xffff) + (sum >> 16));
}
enum class IPProto : uint8_t { ICMP = 0x1, IGMP = 0x2, UDP = 0x11, ICMPv6 = 58 };

enum IPVersion {
  V4 = 4,
  V6 = 6
};

struct IPAddr;
struct IPv4Addr : public std::array<uint8_t, 4> {
  static IPv4Addr any() {
    return {0, 0, 0, 0};
  }

  static IPv4Addr all_systems() {
    return {224, 0, 0, 1};
  }

  static IPv4Addr all_routers() {
    return {224, 0, 0, 2};
  }

  friend std::ostream &operator<<(std::ostream &os, const IPv4Addr &addr) {
    os << std::format("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
    return os;
  }

  bool is_local() const {
    return (*this)[0] == 127;
  }

  bool is_broadcast() const {
    return ((*this)[0] == 255) && ((*this)[1] == 255) && ((*this)[2] == 255) && ((*this)[3] == 255);
  }

  bool is_directed_broadcast(uint8_t prefix_len) {
    auto this_bits = AsBits {*this};
    return std::ranges::all_of(this_bits.begin() + prefix_len,
                                this_bits.end(), [](bool b) { return b; });
  }

  bool is_multicast() const {
    return ((*this)[0] & 0xe0) == 0xe0;
  }

  HWAddr multicast_haddr() const {
    return {0x01, 0x00, 0x5e, static_cast<uint8_t>((*this)[1] & 0x7f), (*this)[2], (*this)[3]};
  }

  IPv4Addr& operator=(const IPAddr&);
  operator IPAddr() const;
};

struct IPAddr : public std::array<uint8_t, 16> {
  static IPAddr from_v4(IPv4Addr v4_addr) {
    return {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, v4_addr[0], v4_addr[1], v4_addr[2], v4_addr[3]};
  }

  static IPAddr loopback() {
    return {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  }

  static IPAddr all_nodes() {
    return {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  }

  static IPAddr all_routers() {
    return {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
  }

  static IPAddr unicast_ll(std::array<uint8_t, 8> ident) {
    return {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ident[0], ident[1], ident[2], ident[3], ident[4], ident[5], ident[6], ident[7]};
  }

  static IPAddr solicited_node(IPAddr sol_addr) {
    return {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, sol_addr[13], sol_addr[14], sol_addr[15]};
  }

  static IPAddr any() {
    return {};
  }

  IPAddr as_prefix_for(std::array<uint8_t, 8> ident, uint8_t prefix_size) {
    IPAddr new_addr {};
    AsBits this_bits {*this};
    AsBits new_bits {new_addr};
    AsBits ident_bits {ident};
    std::copy(this_bits.begin(), this_bits.begin() + prefix_size, new_bits.begin());
    std::copy(ident_bits.begin() + (ident_bits.size() - prefix_size), ident_bits.end(), new_bits.begin() + prefix_size);
    return new_bits.value;
  }

  uint8_t prefix_len(uint8_t prefix) {
    return prefix + (is_v4() ? 96 : 0);
  }

  bool is_directed_broadcast(uint8_t prefix_len) {
    return is_v4() && v4().is_directed_broadcast(prefix_len - 96);
  }

  bool is_v4() const { 
    return *this == IPAddr::from_v4(v4());
  }

  IPv4Addr v4() const { 
    return {(*this)[12], (*this)[13], (*this)[14], (*this)[15]};
  }

  IPVersion version() const {
    return is_v4() ? IPVersion::V4 : IPVersion::V6;
  }

  friend std::ostream &operator<<(std::ostream &os, const IPAddr &addr) {
    if (addr.is_v4()) {
      os << addr.v4();
    } else {
      for (size_t i = 0; i < 15; i++)
        os << std::format("{:02x}:", addr[i]);
      os << std::format("{:02x}", addr[15]);
    }
    return os;
  }

  bool is_any() const {
    return (*this) == IPAddr{};
  }

  bool is_link_local() const {
    return (*this) == IPAddr {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (*this)[8], (*this)[9], (*this)[10], (*this)[11], (*this)[12], (*this)[13], (*this)[14], (*this)[15]};
  }

  bool is_loopback() const {
    return (*this == IPAddr::loopback()) || (is_v4() && v4().is_local());
  }

  bool is_broadcast() const {
    return is_v4() && v4().is_broadcast();
  }
  
  bool is_multicast() const {
    return ((*this)[0] == 0xff) || (is_v4() && v4().is_multicast());
  }

  HWAddr multicast_haddr() const {
    if (is_v4()) {
      return v4().multicast_haddr();
    } else {
      return {0x33, 0x33, (*this)[12], (*this)[13], (*this)[14], (*this)[15]};
    }
  }
  
  uint32_t sum() const {
    std::span<const uint16_t> words {reinterpret_cast<const uint16_t*>(this), 8};
    return std::accumulate(words.begin(), words.end(), 0, [](uint32_t sum, uint16_t word) { return sum + word; });
  }
};


inline IPv4Addr::operator IPAddr() const {
  return IPAddr::from_v4(*this);
}
inline IPv4Addr& IPv4Addr::operator=(const IPAddr& ip) {
  assert(ip.is_v4());
  *this = ip.v4();
  return *this;
}

} // namespace jay

namespace std {
} // namespace std
