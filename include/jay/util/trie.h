#pragma once
#include "jay/util/traits.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <ranges>
#include <stack>
#include <iostream>

namespace jay {
template <typename T>
  requires IsArrayLike_v<T> && std::is_same_v<RemoveExtent_t<T>, uint8_t>
struct AsBits {
private:
  struct BitRef {
    operator bool() const { return (*as_bits)[index]; }

    BitRef &operator=(bool state) { as_bits->set(index, state); return *this; }

    AsBits<T>* as_bits;
    size_t index;
  };
  struct Iterator {
    using value_type = bool;
    using difference_type = ssize_t;
    using reference = BitRef;

    Iterator &operator+=(size_t increment) {
      index += increment;
      return *this;
    }
    Iterator &operator++() {
      *this += 1;
      return *this;
    }
    Iterator operator++(int) {
      Iterator it = *this;
      ++(*this);
      return it;
    }
    Iterator operator+(size_t increment) {
      Iterator it = *this;
      it += increment;
      return it;
    }
    reference operator*() const { return {as_bits, index}; }

    size_t operator-(const Iterator &rhs) { return index - rhs.index; }
    bool operator==(const Iterator &) const = default;

    AsBits<T>* as_bits;
    size_t index;
  };
  static const size_t SIZE = sizeof(T);

public:
  std::reference_wrapper<T> value;
  size_t length;

  AsBits(T& value, size_t length = 8*sizeof(T)) : value(value), length(length) {}

  bool operator[](size_t index) const { return (value.get()[index / 8] >> (7 - index % 8)) & 0x1; }

  void set(size_t index, bool state) {
    size_t offset = 7 - index % 8;
    value.get()[index / 8] = (value.get()[index / 8] & ~(1 << offset)) | (state << offset);
  }

  size_t size() const { return length; }

  Iterator begin() { return {this, 0}; }

  Iterator end() { return {this, size()}; }
};

template <typename TKey, typename TVal> class BitTrie {
public:
  struct Node {
    Node() = default;

    template <typename... ArgT>
    Node(TKey key, size_t key_len, ArgT &&...args)
        : key(key), key_len(key_len), value(std::make_unique<TVal>(std::forward<ArgT>(args)...)) {
    }

    Node(TKey key, size_t key_len, std::unique_ptr<TVal> value)
        : key(key), key_len(key_len), value(std::move(value)) {}

    TKey key {};
    size_t key_len = 0;

    std::unique_ptr<Node> left = nullptr, right = nullptr;
    std::unique_ptr<TVal> value = nullptr;

    template <typename... ArgT>
    Node *split(TKey new_key, size_t new_key_len, size_t offset, ArgT &&...args) {
      auto new_node =
          std::make_unique<Node>(new_key, new_key_len, std::forward<ArgT>(args)...);
      AsBits new_key_bits {new_key, new_key_len};
      if (offset < key_len) {
        std::unique_ptr<Node> old_node =
            std::make_unique<Node>(key, key_len, std::move(value));
        old_node->left = std::move(left);
        old_node->right = std::move(right);

        key_len = offset;
        value = nullptr;

        if (new_key_bits[offset]) {
          left = std::move(old_node);
          right = std::move(new_node);
          return right.get();
        } else {
          left = std::move(new_node);
          right = std::move(old_node);
          return left.get();
        }
      } else if (offset < new_key_bits.size()) {
        if (new_key_bits[offset]) {
          right = std::move(new_node);
          return right.get();
        } else {
          left = std::move(new_node);
          return left.get();
        }
      } else {
        value = std::make_unique<TVal>(std::forward<ArgT>(args)...);
        return this;
      }
    }
  };
private:
  static const size_t KEY_FULL_SIZE = 8 * sizeof(TKey);
  struct EndSentinel {};

  struct InorderIterator {
    using value_type = std::pair<TKey, TVal*>;
    using difference_type = ptrdiff_t;

    InorderIterator() = default;
    InorderIterator(Node* root) {
      if (root->left.get() == nullptr) {
        stack.push(root);
        if (root->value.get() == nullptr)
          (*this)++;
      } else {
        visit_node(root);
      }
    }

    value_type operator*() const {
      return std::make_pair(stack.top()->key, stack.top()->value.get());
    }

    InorderIterator& operator++() {
      Node* top = stack.top();
      stack.pop();
      if (top->right != nullptr) {
        visit_node(top->right.get());
      }

      if ((stack.size() > 0) && (stack.top()->value == nullptr)) {
        return ++(*this);
      }

      return *this;
    }

    InorderIterator operator++(int) {
      InorderIterator it = *this;
      ++(*this);
      return it;
    }

    bool operator==(const InorderIterator&) const = default;

    std::stack<Node*> stack;
  private:
    void visit_node(Node* node) {
      stack.push(node);
      Node* left_node = node->left.get();
      while (left_node != nullptr) {
        stack.push(left_node);
        left_node = left_node->left.get();
      }
    }
  };
  std::unique_ptr<Node> root;

public:
  
  struct MatchIterator {
    using value_type = Node;
    using difference_type = ptrdiff_t;

    MatchIterator(Node *node, TKey key, size_t key_len)
        : _node(node), key(key), search_key(this->key, key_len), search_offset(0) {}

    MatchIterator& operator++() {
      AsBits node_bits {_node->key, _node->key_len};
      auto mismatch = std::ranges::mismatch(
          node_bits.begin() + search_offset, node_bits.end(),
          search_key.begin() + search_offset, search_key.end());
      size_t mismatch_off = std::distance(node_bits.begin(), mismatch.in1);
      search_offset = mismatch_off;
      if (search_offset == search_key.size()) {
        end = true;
      } else if (mismatch_off == _node->key_len) {
        bool search_bit = *mismatch.in2;
        if (search_bit && (_node->right != nullptr))
          _node = _node->right.get();
        else if (!search_bit && (_node->left != nullptr))
          _node = _node->left.get();
        else
          end = true;
      } else {
        end = true;
      }
      return *this;
    }

    MatchIterator operator++(int) {
      MatchIterator it = *this;
      ++(*this);
      return it;
    }

    bool is_full_match() {
      return std::ranges::equal(search_key, AsBits {_node->key, _node->key_len});
    }

    bool operator==(const EndSentinel &) const { return end; }

    value_type &operator*() const { return *_node; }

    bool end = false;
    Node *_node;
    TKey key;
    AsBits<TKey> search_key;
    size_t search_offset;
  };

  MatchIterator match_begin(TKey key, size_t key_len = KEY_FULL_SIZE) {
    return {root.get(), key, key_len};
  }

  EndSentinel match_end() { return {}; }

  BitTrie() : root(std::make_unique<Node>()) {}
  template <typename... ArgT>
  TVal &emplace(TKey key, size_t key_len, ArgT &&...args) {
    auto it = match_begin(key, key_len);
    for (; it != match_end(); it++) {
    }
    Node* new_node = (*it).split(key, key_len, it.search_offset,
                       std::forward<ArgT>(args)...);
    return *new_node->value;
  }

  bool contains(TKey key, size_t key_len = KEY_FULL_SIZE) {
    auto it = match_begin(key, key_len);
    for (; it != match_end(); it++) {
    }
    return it.is_full_match();
  }

  TVal &at(TKey key, size_t key_len = KEY_FULL_SIZE) {
    auto it = match_begin(key, key_len);
    for (; it != match_end(); it++) {
    }
    if (it.is_full_match()) {
      return *(*it).value;
    } else {
      return *(*it).split(key, key_len, it.search_offset)->value;
    }
  }

  std::tuple<TKey, TVal*, size_t> match_longest(TKey key, size_t key_len = KEY_FULL_SIZE) {
    auto it = match_begin(key, key_len);
    for (; it != match_end(); it++) {}
    return std::make_tuple((*it).key, (*it).value.get(), it.search_offset);
  }

  void erase(TKey key, size_t key_len = KEY_FULL_SIZE) {
    auto it = match_begin(key, key_len);
    auto prev_prev_it = it;
    for (auto prev_it = it; it != match_end(); prev_prev_it = prev_it, prev_it = it++) {
    }
    if (!it.is_full_match())
      return;

    Node& node = *it;
    if (&node == root.get()) {
      node.value = nullptr;
    }

    if ((node.left != nullptr) && (node.right != nullptr)) {
      node.value = nullptr;
    } else {
      Node& prev_node = *prev_prev_it;
      bool child_side = (&node == prev_node.right.get());
      (child_side ? prev_node.right : prev_node.left) = std::move((node.right != nullptr) ? node.right : node.left);
    }
  }

  TVal* tree_root() {
    return root->value.get();
  }

  InorderIterator begin() {
    return {root.get()};
  }

  InorderIterator end() {
    return {};
  }
};
} // namespace jay
