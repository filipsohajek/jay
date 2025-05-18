#pragma once

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <iterator>
#include <type_traits>
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
  struct Iterator {
    using value_type = std::remove_cv_t<T>;
    using difference_type = ptrdiff_t;
    using iterator_category = std::bidirectional_iterator_tag;
    using pointer = value_type *;
    using reference = value_type &;

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
    Iterator operator+(int shift) { return {idx + shift, vec}; }
    Iterator operator-(int shift) { return {idx - shift, vec}; }

    T &operator*() const { return (*vec)[idx]; }

    bool operator==(const Iterator &other) const { return (idx == other.idx); }
    bool operator<(const Iterator &other) const { return idx < other.idx; }
    bool operator>(const Iterator &other) const { return other < *this; }
    bool operator<=(const Iterator &other) const { return !(*this > other); }
    bool operator>=(const Iterator &other) const { return !(*this < other); }

    difference_type operator-(const Iterator &other) const {
      return idx - other.idx;
    }

    size_t idx;
    SmallVec *vec;
  };

  T &operator[](size_t idx) {
    if (idx >= S) {
      return overflow_vec[idx - S];
    } else {
      return small_arr[idx];
    }
  }

  template <typename... ArgT> Iterator emplace(Iterator it, ArgT &&...args) {
    if (_size >= S) {
      overflow_vec.resize(overflow_vec.size() + 1);
    }
    if (it != end())
      std::ranges::move_backward(it, end(), end() + 1);
    new (std::addressof(*it)) T(std::forward<ArgT>(args)...);
    _size += 1;
    return it;
  }

  template <typename... ArgT> T &emplace_back(ArgT &&...args) {
    return *emplace(end(), std::forward<ArgT>(args)...);
  }

  Iterator erase(Iterator start, Iterator stop) {
    if (stop <= start)
      return stop;
    for (auto src_it = stop, dst_it = start; src_it != end();
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
    return start;
  }

  Iterator erase(Iterator it) { return erase(it, it + 1); }

  auto begin() { return Iterator{0, this}; }
  auto end() { return Iterator{_size, this}; }

  size_t size() const { return _size; }

private:
  size_t _size = 0;
  std::array<T, S> small_arr;
  std::vector<T> overflow_vec;
};
} // namespace jay
