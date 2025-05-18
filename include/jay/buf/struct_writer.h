#pragma once

#include "jay/util/traits.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

#define NATIVE_IS_NETWORK (BYTE_ORDER == BIG_ENDIAN)
namespace jay {

template <typename T>
concept IsTriviallySerializable = std::is_fundamental_v<T> || std::is_enum_v<T>;
template <typename T>
concept IsFundamentalArrayLike = (IsSubscriptable<T> && IsArrayLike_v<T> &&
                                  IsTriviallySerializable<RemoveExtent_t<T>>);

/// A non-owning read-write cursor into a buffer. Handles bounds checking and
/// network byteorder conversions.
class StructWriter {
public:
  StructWriter(std::span<uint8_t> buffer) : buffer(buffer) {};

  template <typename T> T swap_byteorder(T in) const {
    union {
      T data;
      std::array<uint8_t, sizeof(T)> bytes;
    } data{in};

    for (size_t i = 0; i < sizeof(T) / 2; i++) {
      uint8_t tmp = data.bytes[i];
      data.bytes[i] = data.bytes[sizeof(T) - i - 1];
      data.bytes[sizeof(T) - i - 1] = tmp;
    }

    return data.data;
  }

  /// Read a (trivially serializable) value at the offset in the buffer, in
  /// network byte order if `network`, in little-endian order otherwise.
  ///
  /// May make unaligned reads.
  template <IsTriviallySerializable T>
  T read(size_t offset, bool network = true) const {
    T data = *std::launder(reinterpret_cast<const T *>(buffer.data() + offset));
    if (network ^ NATIVE_IS_NETWORK) {
      data = swap_byteorder(data);
    }

    return data;
  }

  /// Write a (trivially-serializable) value at the offset in the buffer,
  /// in network byte ordere if `network`, in little-endian order otherwise.
  ///
  /// May make unaligned writes.
  template <IsTriviallySerializable T>
  void write(size_t offset, T data, bool network = true) const {
    if (network ^ NATIVE_IS_NETWORK) {
      data = swap_byteorder(data);
    }
    *std::launder(reinterpret_cast<T *>(buffer.data() + offset)) = data;
  }

  /// Read an array (element by element) of (trivially serializable) values at
  /// the offset. See the respective `read` specialization.
  template <IsFundamentalArrayLike T>
  T read(size_t offset, bool network = true) const {
    using Tval = RemoveExtent_t<T>;
    T val;
    for (size_t i = 0; i < sizeof(T) / sizeof(Tval); i++) {
      val[i] = read<Tval>(offset + i * sizeof(Tval), network);
    }
    return val;
  }

  /// Write an array (element by element) of (trivially serializable) values at
  /// the offset. See the respective `write` specialization.
  template <IsFundamentalArrayLike T>
  void write(size_t offset, T data, bool network = true) const {
    using Tval = RemoveExtent_t<T>;
    for (size_t i = 0; i < sizeof(T) / sizeof(Tval); i++) {
      write<Tval>(offset + i * sizeof(Tval), data[i], network);
    }
  }

  auto span() const { return buffer; }
  size_t size() const { return buffer.size(); }
  StructWriter slice(size_t offset, size_t size = std::dynamic_extent) {
    return {buffer.subspan(offset, size)};
  }

  bool operator==(const StructWriter &other) const {
    return (buffer.data() == other.buffer.data()) &&
           (buffer.size() == other.buffer.size());
  }

  void reset() { std::ranges::fill(buffer, 0); }

private:
  std::span<uint8_t> buffer;
};

template <typename T>
concept IsBufWriteable =
    IsTriviallySerializable<T> || IsFundamentalArrayLike<T>;
template <typename T>
concept IsBufReadable = IsTriviallySerializable<T> || IsFundamentalArrayLike<T>;

} // namespace jay
