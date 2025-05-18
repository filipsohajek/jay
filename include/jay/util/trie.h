#pragma once
#include "jay/util/traits.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <ranges>
#include <stack>

namespace jay {
template <typename T>
  requires IsArrayLike_v<T> && std::is_same_v<RemoveExtent_t<T>, uint8_t>
struct AsBits {
private:
  struct BitRef {
    operator bool() const { return (*as_bits)[index]; }

    BitRef &operator=(bool state) { as_bits->set(index, state); }

    AsBits<T> *as_bits;
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
      (*this)++;
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

    AsBits<T> *as_bits;
    size_t index;
  };
  static const size_t SIZE = sizeof(T);

public:
  T value;
  size_t length;

  bool operator[](size_t index) { return value[index / 8] >> (7 - index % 8); }

  void set(size_t index, bool state) {
    size_t offset = 7 - index % 8;
    value[index / 8] = (value[index / 8] & ~(1 << offset)) | (state << offset);
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
    Node(AsBits<TKey> key, ArgT &&...args)
        : key(key), value(std::make_unique<TVal>(std::forward<ArgT>(args)...)) {
    }

    Node(AsBits<TKey> key, std::unique_ptr<TVal> value)
        : key(key), value(std::move(value)) {}

    AsBits<TKey> key = {TKey(), 0};

    std::unique_ptr<Node> left = nullptr, right = nullptr;
    std::unique_ptr<TVal> value = nullptr;

    template <typename... ArgT>
    Node *split(AsBits<TKey> new_key, size_t offset, ArgT &&...args) {
      auto new_node =
          std::make_unique<Node>(new_key, std::forward<ArgT>(args)...);
      if (offset < key.size()) {
        std::unique_ptr<Node> old_node =
            std::make_unique<Node>(key, std::move(value));
        old_node->left = std::move(left);
        old_node->right = std::move(right);

        key = {key.value, offset};
        value = nullptr;

        if (new_key[offset]) {
          left = std::move(old_node);
          right = std::move(new_node);
          return right.get();
        } else {
          left = std::move(new_node);
          right = std::move(old_node);
          return left.get();
        }
      } else if (offset < new_key.size()) {
        if (new_key[offset]) {
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
      return std::make_pair(stack.top()->key.value, stack.top()->value.get());
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

    MatchIterator(Node *node, AsBits<TKey> search_key)
        : _node(node), search_key(search_key), search_offset(0) {}

    MatchIterator& operator++() {
      auto mismatch = std::ranges::mismatch(
          _node->key.begin() + search_offset, _node->key.end(),
          search_key.begin() + search_offset, search_key.end());
      size_t mismatch_off = std::distance(_node->key.begin(), mismatch.in1);
      search_offset = mismatch_off;
      if (search_offset == search_key.size()) {
        end = true;
      } else if (mismatch_off == _node->key.size()) {
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
      return std::ranges::equal(
          search_key.begin(), search_key.end(),
          _node->key.begin(), _node->key.end());
    }

    bool operator==(const EndSentinel &) const { return end; }

    value_type &operator*() const { return *_node; }

    bool end = false;
    Node *_node;
    AsBits<TKey> search_key;
    size_t search_offset;
  };

  MatchIterator match_begin(TKey key, size_t key_len) {
    return {root.get(), {key, key_len}};
  }

  EndSentinel match_end() { return {}; }

  BitTrie() : root(std::make_unique<Node>()) {}
  template <typename... ArgT>
  TVal &emplace(TKey key, size_t key_len, ArgT &&...args) {
    auto it = match_begin(key, key_len);
    for (; it != match_end(); it++) {
    }
    Node* new_node = (*it).split({key, key_len}, it.search_offset,
                       std::forward<ArgT>(args)...);
    return *new_node->value;
  }

  bool contains(TKey key, size_t key_len) {
    auto it = match_begin(key, key_len);
    for (; it != match_end(); it++) {
    }
    return it.is_full_match();
  }

  TVal &at(TKey key, size_t key_len) {
    auto it = match_begin(key, key_len);
    for (; it != match_end(); it++) {
    }
    if (it.is_full_match()) {
      return (*it).value;
    } else {
      return (*it).split({key, key_len}, it.search_offset)->value;
    }
  }

  std::pair<TKey, TVal*> match_longest(TKey key, size_t key_len) {
    auto it = match_begin(key, key_len);
    for (; it != match_end(); it++) {}
    return std::make_pair((*it).key.value, (*it).value.get());
  }

  void erase(TKey key, size_t key_len) {
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

  InorderIterator begin() {
    return {root.get()};
  }

  InorderIterator end() {
    return {};
  }
};
} // namespace jay
