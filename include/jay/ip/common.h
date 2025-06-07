#pragma once

#include "jay/buf/sbuf.h"
#include <array>
#include <cstdint>
#include <numeric>
#include <ostream>
#include <format>

namespace jay::ip {
enum class IPProto : uint8_t { ICMP = 0x1, UDP = 0x11 };

enum IPVersion {
  V4 = 4,
};

struct IPv4Addr : public std::array<uint8_t, 4> {
  static IPv4Addr any() {
    return {0, 0, 0, 0};
  }

  uint32_t csum() const {
    uint32_t w1 = ((*this)[0] << 16) | (*this)[1];
    uint32_t w2 = ((*this)[2] << 16) | (*this)[3];
    return w1 + w2;
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

  bool is_multicast() const {
    return ((*this)[0] & 0xe0) == 0xe0;
  }
};

struct IPAddr : public std::variant<IPv4Addr> {
  using std::variant<IPv4Addr>::variant;
  bool is_v4() const { return std::holds_alternative<IPv4Addr>(*this); }
  IPv4Addr v4() const { return std::get<IPv4Addr>(*this); }
  IPVersion version() const {
    return is_v4() ? IPVersion::V4 : IPVersion(0);
  }

  friend std::ostream &operator<<(std::ostream &os, const IPAddr &addr) {
    if (std::holds_alternative<IPv4Addr>(addr)) {
      os << std::get<IPv4Addr>(addr);
    }
    return os;
  }

  bool is_any() const {
    if (std::holds_alternative<IPv4Addr>(*this)) {
      return std::get<IPv4Addr>(*this) == IPv4Addr::any(); 
    }
    return false;
  }

  bool is_local() const {
    return std::visit([](const auto& addr) { return addr.is_local(); }, *this);
  }

  bool is_broadcast() const {
    return std::visit([](const auto& addr) { return addr.is_broadcast(); }, *this);
  }
  
  bool is_multicast() const {
    return std::visit([](const auto& addr) { return addr.is_multicast(); }, *this);
  }
  
  uint32_t csum() const {
    return std::visit([](const auto& addr) { return addr.csum(); }, *this);
  }
};

inline uint16_t inet_csum(std::span<uint8_t> data, uint32_t init_sum = 0) {
  if (data.size() > 65535)
    throw std::out_of_range(
        "internet checksum of data of size >65536 is not implemented");
  std::span<uint16_t> words{reinterpret_cast<uint16_t *>(data.data()),
                            data.size() / 2};
  uint32_t sum =
      std::accumulate(words.begin(), words.end(), init_sum,
                      [](uint32_t acc, uint16_t word) { return acc + uint32_t(word); });
  return ~static_cast<uint16_t>((sum & 0xffff) + (sum >> 16));
}

inline uint16_t inet_csum(Buf &buf, uint32_t init_sum = 0) {
  uint32_t sum = 0;
  for (auto it = buf.begin(); it != buf.end(); it = it.next_chunk()) {
    std::span<uint16_t> words{
        reinterpret_cast<uint16_t *>(it.contiguous().data()),
        it.contiguous().size() / 2};
    sum += std::accumulate(
        words.begin(), words.end(), init_sum,
        [](uint32_t acc, uint16_t word) { return acc + uint32_t(word); });
  }
  return ~static_cast<uint16_t>((sum & 0xffff) + (sum >> 16));
}

} // namespace jay

namespace std {
} // namespace std
