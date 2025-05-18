#pragma once
#include "jay/ip/common.h"
#include <cstdint>
#include <tuple>
#include <unordered_map>

/// Hashtable implementation. Currently using [std::unordered_map] with added
/// [std::hash] specializations for array and tuple types.

namespace std {
template <typename... Ts> struct hash<std::tuple<Ts...>> {
  size_t operator()(const std::tuple<Ts...> &tuple) const noexcept {
    return [&]<size_t ...I>(std::index_sequence<I...>) {
      size_t hash = 0;
      [[maybe_unused]] size_t _hashes[sizeof...(I)] = {
        (hash = (hash + 0xbb40e64d) ^ std::hash<Ts> {}(std::get<I>(tuple)))...
      };
      return hash;
    }(std::make_index_sequence<sizeof...(Ts)>());
  }
};

template <typename T, size_t S> struct hash<std::array<T, S>> {
  size_t operator()(const std::array<T, S> &arr) const noexcept {
    size_t hash = 0;
    std::hash<T> val_hasher{};

    for (auto &val : arr) {
      hash = val_hasher(val) ^ (0xbb40e64d + hash);
    }

    return hash;
  }
};
template <> struct hash<jay::ip::IPv4Addr> : public hash<std::array<uint8_t, 4>> {};

template <>
struct hash<jay::ip::IPAddr> : public hash<std::variant<jay::ip::IPv4Addr>> {};
} // namespace std

namespace jay {
template <typename K, typename V> using hash_table = std::unordered_map<K, V>;
} // namespace jay
