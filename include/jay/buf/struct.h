#pragma once
#include "jay/buf/struct_writer.h"
#include "jay/util/result.h"
#include <cstddef>
#include <iostream>
#include <limits>

namespace jay {
enum class BufError { OUT_OF_BOUNDS, NO_SIZE_HINT };

/// CRTP template for representing (de)serializable structures such as
/// protocol headers. The implementor itself should not store the structure
/// data, but only a pointer to an underlying buffer, providing transparent
/// access to the fields (see the `*Field` classes and associated
/// `STRUCT_FIELD_` macros).
template <typename Ts, typename Terr = BufError> class BufStruct {
public:
  using ErrorType = Terr;
  BufStruct() : cur(StructWriter({})) {};
  BufStruct(const BufStruct &) = default;
  BufStruct &operator=(const BufStruct &) = default;
  BufStruct(BufStruct &&) = default;
  BufStruct &operator=(BufStruct &&) = default;

  static Result<Ts, Terr> read(StructWriter cur) {
    size_t size = Ts::size_hint();
    if (size > cur.size())
      return ResultError<Terr>{Terr::OUT_OF_BOUNDS};
    Ts strct = Ts{cur};
    if (strct.size() > cur.size())
      return ResultError<Terr>{Terr::OUT_OF_BOUNDS};
    strct.cur = cur.span().subspan(0, strct.size());
    return strct;
  }

  static Result<Ts, Terr> construct(StructWriter cur) {
    Ts strct = Ts{cur};
    auto size = Ts::size_hint();
    if (size > cur.size())
      return ResultError<Terr>{Terr::OUT_OF_BOUNDS};
    strct.cur = cur.span().subspan(0, size);
    return strct; 
  }

  static size_t size_hint() {
    return std::numeric_limits<size_t>::max();
  }

  StructWriter cursor() const { return cur; }

protected:
  BufStruct(StructWriter cur) : cur(cur) {}
  StructWriter cur;
};

template <typename T>
concept IsBufStruct = std::is_base_of_v<BufStruct<T, typename T::ErrorType>, T>;

/// A structure field abstraction, providing transparent read and write access
/// to a serializable ([IsBufReadable] and [IsBufWriteable], or [IsBufStruct])
/// type at a specific place in memory.
///
/// The template contains the following conditional features:
/// - if `T` is [IsBufReadable]: conversion operator to `T`
/// - if `T` is [IsBufWriteable]: assignment operator overload for `T`
/// - if `T` is [IsBufStruct]: `read` and `construct` methods matching the
/// BufStruct semantics
template <typename T, bool NBO = true> struct Field {
  using Type = T;

  Field(StructWriter cur) : cur(cur) {};
  Field(const Field &) = default;
  Field(Field &&) = default;

  // prevent mistakenly "assigning" the value of another field
  Field &operator=(const Field &) = delete;
  Field &operator=(Field &&) = delete;

  void operator=(const T &data) const
    requires IsBufWriteable<T> 
  {
    cur.write<T>(0, data, NBO);
  }

  template<typename Ta>
  requires std::is_assignable_v<T, Ta>
  void operator=(const Ta& data) const {
    T value = T(*this);
    value = data;
    *this = value;
  }

  operator T() const
    requires IsBufReadable<T> 
  {
    return cur.read<T>(0, NBO);
  }

  T value() const { return *this; }

  template <typename... RArgT>
  auto read(RArgT &&...args)
    requires IsBufStruct<T>
  {
    return T::read(cur, std::forward<RArgT>(args)...);
  }

  template <typename... CArgT>
  auto construct(CArgT &&...args)
    requires IsBufStruct<T>
  {
    return T::construct(cur, std::forward<CArgT>(args)...);
  }

  bool operator==(const Field<T> &rhs) { return T(rhs) == *this; }

  StructWriter cur;
};

template <typename Ts> struct DefaultTagAccessor {
  static const decltype(Ts::UNION_TAG) TAG = Ts::UNION_TAG;
};
/// A structure field that can take on several types depending on the value of
/// another field (discriminator).
///
/// The `TDisc` template parameter is the type of the discriminator _field_,
/// `Ts` are the permissible types, which must be [IsBufStruct] and,
/// furthermore, readable using `Ts::read` with no read arguments. `TagAccessor`
/// is a single-parameter template with a static member TAG giving the value of
/// the discriminiator field corresponding to the provided type.
template <typename TDisc, template <typename> typename TagAccessor,
          typename... Ts>
  requires(IsBufStruct<Ts> && ...)
struct TaggedUnionField {
  TaggedUnionField(StructWriter cur, TDisc disc) : cur(cur), disc(disc) {}
  using DiscType = TDisc::Type;

  /// Read the field and construct a [std::variant] instance with the currently
  /// present type set and with [std::monostate] if the current type tag does
  /// not correspond to any type.
  ///
  /// Currently unpacks the read [Result] with no error handling (TODO, but the
  /// parent structure can handle the bulk of the validation).
  std::variant<std::monostate, Ts...> variant() const {
    std::variant<std::monostate, Ts...> out;
    (
        [&]() {
          if constexpr (requires { TagAccessor<Ts>::TAG; })
            if (DiscType(disc) == TagAccessor<Ts>::TAG)
              out = Ts::read(cur).value();
        }(),
        ...);
    return out;
  }

  /// Construct the structure `To` in the union. Accepts [std::monostate] as
  /// `To`, in which case the discriminator field is zeroed.
  template <typename To, typename... CArgT>
  Result<To, typename To::ErrorType> set(CArgT &&...constr_args) {
    if constexpr (!std::is_same_v<To, std::monostate>) {
      disc = DiscType(TagAccessor<To>::TAG);
    } else {
      disc = DiscType(0);
    }
    return To::construct(cur, std::forward<CArgT>(constr_args)...);
  }

  /// Return the size of the currently present structure, returning a large
  /// number if the current type tag does not correspond to any type.
  size_t size() const {
    return std::visit(
        [](auto strct) {
          if constexpr (std::is_same_v<decltype(strct), std::monostate>) {
            return std::numeric_limits<size_t>::max() / 2;
          } else {
            return strct.size();
          }
        },
        variant());
  }

  StructWriter cur;
  TDisc disc;
};

/// A structure bitfield represented by `Tr` at the (bit) offset `Offset` from
/// the start and of `Length` bits length. Optionally accpets `Mult`, which
/// gives the multiplier of the stored value (e.g. for `Mult==2` the read value
/// is multiplied by two and the written value is divided by two before
/// writing).
///
/// Reads `ceil(Length/8)` bytes from the underlying buffer, which may cause
/// unaligned reads in certain bitfields.
template <typename Tr, size_t Offset, size_t Length, size_t Mult = 1>
  requires std::integral<Tr> || std::is_enum_v<Tr>
struct BitField {
private:
  static const size_t END = Offset + Length;
  static const size_t START_OFFSET = Offset / 8;
  static const size_t B_END = (END + 7) / 8;
  static const size_t B_LEN = B_END - START_OFFSET;
  static const size_t SHIFT_LEN = 8 * B_END - END;
  using DeserType = std::conditional_t<
      B_LEN <= 1, uint8_t,
      std::conditional_t<B_LEN <= 2, uint16_t,
                         std::conditional_t<B_LEN <= 4, uint32_t, void>>>;
  static const DeserType MASK = ((DeserType{1} << Length) - 1) << SHIFT_LEN;

public:
  using Type = Tr;
  void operator=(const Tr &data) const {
    DeserType masked_data =
        MASK & (static_cast<DeserType>(data / Mult) << SHIFT_LEN);
    DeserType prev_value = cur.read<DeserType>(START_OFFSET, true);
    DeserType new_value = (prev_value & ~MASK) | masked_data;
    cur.write<DeserType>(START_OFFSET, new_value, true);
  }

  operator Tr() const {
    DeserType deser_val = cur.read<DeserType>(START_OFFSET, true);
    return Tr(((MASK & deser_val) >> SHIFT_LEN) * Mult);
  }

  Tr value() const {
    return *this;
  }

  bool operator==(const BitField<Tr, Offset, Length> &rhs) {
    return Tr(rhs) == *this;
  }

  StructWriter cur;
};

/// A structure field representing an array of variable length (bounded only by
/// the length of the buffer).
template <typename Ti>
  requires IsBufReadable<Ti> || IsBufStruct<Ti>
struct VarArrayField {
  struct Iterator {
    using value_type = Field<Ti>;
    using difference_type = void;

    struct EndSentinel {};

    explicit Iterator(StructWriter cur) : cur(cur), base_cur(cur) {
      end = is_end();
    }

    Field<Ti> operator*() const { return {cur}; }

    Iterator& operator++() {
      if (is_end())
        return *this;
      cur = {cur.span().subspan(cur_size())};
      end = is_end();
      return *this;
    }

    Iterator operator++(int) {
      auto iter = *this;
      ++(*this);
      return iter;
    }

    bool operator==(const EndSentinel &) const {
      return end;
    }

    size_t cur_size() const {
      if constexpr (IsBufReadable<Ti>) {
        return sizeof(Ti);
      } else if constexpr (IsBufStruct<Ti>) {
        return Ti::read(cur)
            .transform([](const Ti &strct) -> size_t { return strct.size(); })
            .value_or(std::numeric_limits<size_t>::max());
      }
    }
  private:
    bool is_end() const { return (cur_size() == 0) || (cur_size() > cur.span().size()); }

    bool end = false;
    StructWriter cur;
    StructWriter base_cur;
  };

  Iterator begin() const { return Iterator(cur); }

  Iterator::EndSentinel end() const {
    return {};
  }

  size_t size() const {
    size_t total_size = 0;
    for (auto it = begin(); it != end(); it++) {
      total_size += it.cur_size();
    }
    return total_size;
  }
  StructWriter cur;
};

#define STRUCT_FIELD(name, offset, type)                                       \
  ::jay::Field<type> name() const { return {{cur.span().subspan(offset)}}; }
#define STRUCT_FIELD_LE(name, offset, type)                                    \
  ::jay::Field<type, false> name() const {                                     \
    return {{cur.span().subspan(offset)}};                                     \
  }
#define STRUCT_BITFIELD(name, offset, length, rtype)                           \
  ::jay::BitField<rtype, offset, length> name() const { return {cur}; }
#define STRUCT_BITFIELD_MULT(name, offset, length, rtype, mult)                \
  ::jay::BitField<rtype, offset, length, mult> name() const { return {cur}; }
#define STRUCT_VARARRAY(name, offset, type)                                    \
  ::jay::VarArrayField<type> name() const {                                    \
    return {cur.span().subspan(offset)};                                       \
  }
#define STRUCT_TAGGED_UNION_ACCESSOR(name, offset, field, accessor, ...)       \
  auto name() const {                                                          \
    return ::jay::TaggedUnionField<decltype(field), accessor, __VA_ARGS__>{    \
        cur.span().subspan(offset), field};                                    \
  }
#define STRUCT_TAGGED_UNION(name, offset, field, ...)                          \
  STRUCT_TAGGED_UNION_ACCESSOR(name, offset, field, ::jay::DefaultTagAccessor, \
                               __VA_ARGS__)

/// Helper trait for accessing the underlying field's type.
template <typename Tf> struct RemoveField {};
template <typename T, bool NBO> struct RemoveField<Field<T, NBO>> {
  using type = T;
};

template <typename T, size_t Off, size_t Len, size_t Mult>
struct RemoveField<BitField<T, Off, Len, Mult>> {
  using type = T;
};

template <typename Tf> using RemoveField_t = RemoveField<Tf>::type;

} // namespace jay
