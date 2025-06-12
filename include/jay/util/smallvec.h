#pragma once

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <iterator>
#include <type_traits>
#include <utility>
#include <vector>

namespace jay {
/// A vector class with small-vector optimizations (holds up to `S` in the class
/// itself and the overflow in a heap-allocated vector).
template <typename T, size_t S> class SmallVec {
public:
  explicit SmallVec(size_t size)
      : _size(size), small_arr{}, overflow_vec(std::max(S, size) - S) {};
  SmallVec() = default;
  SmallVec(std::initializer_list<T> init_list) : _size(init_list.size()) {
    for (auto &&val : init_list) {
      emplace_back(val);
    }
  }
public:
  template<typename Ti>
  struct Iterator {
    using value_type = Ti;
    using difference_type = ptrdiff_t;
    using iterator_category = std::bidirectional_iterator_tag;
    using pointer = value_type *;
    using reference = value_type &;

  private:
    using VecPtrT = std::conditional_t<std::is_const_v<Ti>, const SmallVec*, SmallVec*>;
  public:
    Iterator() = default;
    Iterator(VecPtrT vec, size_t idx) : vec(vec), idx(idx) {}
    template<typename To>
    Iterator(const Iterator<To>& other) : vec(other.vec), idx(other.idx) {} 
    template<typename To>
    Iterator(Iterator<To>&& other) : vec(other.vec), idx(other.idx) {} 
    template<typename To>
    Iterator<Ti>& operator=(const Iterator<To>& other) {
      vec = other.vec;
      idx = other.idx;
      return *this;
    }
    template<typename To>
    Iterator<Ti>& operator=(Iterator<To>&& other) {
      vec = other.vec;
      idx = other.idx;
      return *this;
    }

    Iterator operator++(int) {
      Iterator iter = *this;
      ++(*this);
      return iter;
    }
    Iterator &operator++() {
      idx++;
      return *this;
    }
    Iterator &operator--() {
      idx--;
      return *this;
    }
    Iterator operator--(int) {
      Iterator iter = *this;
      --(*this);
      return iter;
    }
    Iterator operator+(int shift) const { return {vec, idx + shift}; }
    Iterator operator-(int shift) const { return {vec, idx - shift}; }

    reference operator*() const { return (*vec)[idx]; }

    bool operator==(const Iterator &other) const { return (idx == other.idx); }
    bool operator!=(const Iterator &other) const { return (idx != other.idx); }
    bool operator<(const Iterator &other) const { return idx < other.idx; }
    bool operator>(const Iterator &other) const { return other < *this; }
    bool operator<=(const Iterator &other) const { return !(*this > other); }
    bool operator>=(const Iterator &other) const { return !(*this < other); }

    difference_type operator-(const Iterator<Ti> &other) const {
      return idx - other.idx;
    }
    
    VecPtrT vec;
    size_t idx;
  };

  using iterator = Iterator<T>;
  using const_iterator = Iterator<const T>;

  const T &operator[](size_t idx) const {
    if (idx >= S) {
      return overflow_vec[idx - S];
    } else {
      return small_arr[idx];
    }
  }

  T& operator[](size_t idx) {
    return const_cast<T&>(std::as_const(*this)[idx]);
  }

  template <typename... ArgT> iterator emplace(const_iterator it, ArgT &&...args) {
    iterator mut_it {this, it.idx};
    if (_size >= S) {
      overflow_vec.resize(overflow_vec.size() + 1);
    }
    if (it != end())
      std::ranges::move_backward(mut_it, end(), end() + 1);
    new (std::addressof(*mut_it)) T(std::forward<ArgT>(args)...);
    _size += 1;
    return mut_it;
  }

  template <typename... ArgT> T &emplace_back(ArgT &&...args) {
    return *emplace(end(), std::forward<ArgT>(args)...);
  }

  iterator erase(const_iterator start, const_iterator stop) {
    iterator mut_start {this, start.idx};
    iterator mut_stop {this, stop.idx};
    if (stop <= start)
      return mut_stop;
    for (auto src_it = mut_stop, dst_it = mut_start; src_it != end();
         src_it++, dst_it++) {
      new (std::addressof(*dst_it)) T(std::move(*src_it));
      (*src_it).~T();
    }

    size_t n_erased = stop - start;
    if (_size > S) {
      overflow_vec.resize(overflow_vec.size() -
                          std::min(overflow_vec.size(), n_erased));
    }
    _size -= n_erased;
    return mut_start;
  }

  iterator erase(const_iterator it) { return erase(it, it + 1); }

  iterator begin() { return {this, 0}; }
  iterator end() { return {this, _size}; }
  const_iterator begin() const { return {this, 0}; }
  const_iterator end() const { return {this, _size}; }

  size_t size() const { return _size; }

private:
  size_t _size = 0;
  std::array<T, S> small_arr;
  std::vector<T> overflow_vec;
};
} // namespace jay
