#pragma once

#include "jay/util/result.h"
#include "jay/util/smallvec.h"
#include <cassert>
#include <memory>
#include <memory_resource>
#include <span>

namespace jay {
/// A shared owning reference to a part of an in-memory buffer.
///
/// The reference is backed by [std::shared_ptr] together with a per-instance
/// size and offset. This allows referencing arbitrary slices of buffers of
/// various origins, potentially allocated using custom allocators and using
/// user-supplied deleters -- this is useful for zero-copy processing of
/// user-supplied buffers.
///
/// The chunk may be empty, i.e. not pointing to any buffer, but still have a
/// nonzero size. Such chunks are used to represent holes in [Buf].
class BufChunk {
public:
  template <class Alloc = std::pmr::polymorphic_allocator<std::byte>>
  explicit BufChunk(size_t size,
                    const Alloc &alloc = std::pmr::polymorphic_allocator())
      : data(std::allocate_shared<uint8_t[], Alloc>(alloc, size)), _size(size) {
  }

  explicit BufChunk(std::shared_ptr<uint8_t[]> ptr, size_t size, size_t offset)
      : data(std::move(ptr)), offset(offset), _size(size) {}

  BufChunk(const BufChunk &) = default;
  BufChunk &operator=(const BufChunk &) = default;
  BufChunk(BufChunk &&) = default;
  BufChunk &operator=(BufChunk &&) = default;
  BufChunk() = default;

public:
  static BufChunk empty(size_t size) {
    BufChunk chunk;
    chunk._size = size;
    chunk.data = nullptr;
    return chunk;
  }

  uint8_t *begin() { return data.get() + offset; }
  uint8_t *end() { return data.get() + _size; }
  const uint8_t *begin() const { return data.get() + offset; }
  const uint8_t *end() const { return data.get() + _size; }
  size_t size() const { return _size; }

  bool is_empty() const { return data == nullptr; }

  BufChunk slice(size_t slice_off,
                 size_t slice_len = std::dynamic_extent) const {
    if (slice_len == std::dynamic_extent)
      slice_len = _size - slice_off;
    assert(slice_len <= _size);

    BufChunk sliced;
    sliced.data = data;
    sliced.offset = offset + slice_off;
    sliced._size = slice_len;
    return sliced;
  }

private:
  std::shared_ptr<uint8_t[]> data = nullptr;
  size_t offset = 0;
  size_t _size = 0;
};

/// A non-contiguous buffer.
///
/// Consists of a variable amount of chunks ([BufChunk] instances), which are
/// transparently chained together and usable as a range. Some of the chunks may
/// be empty, representing a "hole" in the buffer. Such holes can be filled by
/// another [Buf] or a [BufChunk] in a time linear in the number of chunks. This
/// mechanism is used for example in IP reassembly, where it replaces copying
/// the individual fragments.
///
/// The buffer allows for masking and unmasking a number of bytes from the top
/// of the buffer. When masked, the buffer acts as a buffer of a smaller size
/// until unmasked again.
class Buf {
  /// the number of chunks to store in the class without resorting to further
  /// allocations
  static const size_t SMALL_CHUNK_COUNT = 4;

public:
  template<typename Ti>
  struct Iterator {
    using value_type = Ti;
    using iterator_category = std::bidirectional_iterator_tag;
    using difference_type = ssize_t;
    using pointer = uint8_t *;
    using reference = uint8_t &;

  private:
    using ChunkVecType = SmallVec<BufChunk, SMALL_CHUNK_COUNT>;
    using ChunkItType = std::conditional_t<std::is_const_v<Ti>, ChunkVecType::const_iterator, ChunkVecType::iterator>;
  public:
    Iterator() = default;
    Iterator(ChunkItType chunk_it, size_t chunk_off) : chunk_off(chunk_off), chunk_it(chunk_it) {}
    template<typename To>
    Iterator(const Iterator<To>& other) : chunk_off(other.chunk_off), chunk_it(other.chunk_it) {}
    template<typename To>
    Iterator(Iterator<To>&& other) : chunk_it(other.chunk_it), chunk_off(other.chunk_off) {}
    template<typename To>
    Iterator<Ti>& operator=(const Iterator<To>& other) {
      chunk_it = other.chunk_it;
      chunk_off = other.chunk_off;
      return *this;
    }
    template<typename To>
    Iterator<Ti>& operator=(Iterator<To>&& other) {
      chunk_it = other.chunk_it;
      chunk_off = other.chunk_off;
      return *this;
    }
    
    value_type &operator*() const {
      auto &chunk = *chunk_it;
      return *(chunk.begin() + chunk_off);
    }

    Iterator &operator++() {
      if (chunk_off + 1 < (*chunk_it).size()) {
        chunk_off++;
      } else {
        chunk_it++;
        chunk_off = 0;
      }

      return *this;
    }
    Iterator operator++(int) {
      Iterator iter = *this;
      ++(*this);
      return iter;
    }

    Iterator &operator--() {
      if (chunk_off == 0) {
        chunk_it--;
        chunk_off = (*chunk_it).size() - 1;
      } else {
        chunk_off--;
      }

      return *this;
    }

    Iterator operator--(int) {
      Iterator iter = *this;
      --(*this);
      return iter;
    }

    Iterator operator+(size_t shift) const {
      Iterator it = *this;
      it += shift;
      return it;
    }

    Iterator &operator+=(size_t shift) {
      while ((shift > 0) && (shift >= ((*chunk_it).size() - chunk_off))) {
        shift -= (*chunk_it).size() - chunk_off;
        chunk_it++;
        chunk_off = 0;
      }
      chunk_off += shift;
      return *this;
    }

    Iterator operator-(size_t shift) const {
      Iterator it = *this;
      it -= shift;
      return it;
    }

    Iterator &operator-=(size_t shift) {
      while (shift > chunk_off) {
        shift -= chunk_off + 1;
        chunk_it--;
        chunk_off = (*chunk_it).size() - 1;
      }

      chunk_off -= shift;
      return *this;
    }

    Iterator next_chunk() const { return {chunk_it + 1, 0}; }
    Iterator prev_chunk() const { return {chunk_it - 1, 0}; }
    size_t chunk_offset() const { return chunk_off; }
    const BufChunk &chunk() const { return *chunk_it; }
    BufChunk &chunk() { return *chunk_it; }
    BufChunk sliced_chunk() const { return (*chunk_it).slice(chunk_off); }
    bool is_hole() const { return (*chunk_it).is_empty(); }
    std::span<uint8_t> contiguous() const {
      auto chunk = sliced_chunk();
      return chunk;
    }

    template<typename To>
    bool operator==(const Iterator<To> &other) const {
      return (chunk_off == other.chunk_off) && (chunk_it == other.chunk_it);
    }

    size_t chunk_off;

  public:
    ChunkItType chunk_it;
  };

  using iterator = Iterator<uint8_t>;
  using const_iterator = Iterator<const uint8_t>;
private:
  SmallVec<BufChunk, SMALL_CHUNK_COUNT> chunks;

  // we technically only need the mask_off, but it could get expensive to
  // compute these on every call
  size_t _size = 0;
  iterator masked_start;
  size_t mask_off = 0;
  size_t n_holes = 0;

public:
  template <class Alloc = std::pmr::polymorphic_allocator<std::byte>>
  explicit Buf(size_t size,
               const Alloc &alloc = std::pmr::polymorphic_allocator())
      : _size(size), masked_start(begin(false)) {
    chunks.emplace_back(size, alloc);
  }
  explicit Buf(BufChunk chunk) : chunks({chunk}), masked_start(begin(false)) {}
  Buf() : chunks({}), masked_start(begin(false)) {};

  // the buffer doesn't own the underlying buffers, we can therefore make it
  // copyable, but the copy could still be expensive when the number of chunks
  // is large
  Buf &operator=(const Buf &other) {
    chunks = other.chunks;
    _size = other._size;
    masked_start = iterator {chunks.begin() + other.masked_start.chunk_it.idx, other.masked_start.chunk_off};
    mask_off = other.mask_off;
    n_holes = other.n_holes;
    return *this;
  }
  Buf(const Buf &other) { *this = other; }
  Buf &operator=(Buf &&other) {
    chunks = std::move(other.chunks);
    _size = other._size;
    masked_start = iterator {chunks.begin() + other.masked_start.chunk_it.idx, other.masked_start.chunk_off};
    mask_off = other.mask_off;
    n_holes = other.n_holes;
    return *this;
  }
  Buf(Buf &&other) { *this = other; }

  /// Reserve a _contiguous_ chunk of a given size directly before the currently
  /// masked position. If the masked part of the current chunk is not
  /// sufficient, allocates a new chunk and replaces (without copying) the
  /// appropriate preceding chunks.
  void reserve_before(size_t res_size) {
    if (masked_start.chunk_off >= res_size)
      return; // the current chunk is sufficient

    size_t erased_size;
    iterator insert_pos;
    if (mask_off >= res_size) {
      auto erase_start = masked_start - res_size;
      erased_size = res_size;
      masked_start.chunk_it =
          chunks.erase(erase_start.chunk_it + 1, masked_start.chunk_it);
      masked_start.chunk() = masked_start.chunk().slice(masked_start.chunk_off);
      masked_start.chunk_off = 0; // truncate the current chunk from the head
      erase_start.chunk() = erase_start.chunk().slice(
          0, erase_start
                 .chunk_off); // truncate the new preceding chunk from the tail
      insert_pos = erase_start;
    } else {
      erased_size = mask_off;
      masked_start.chunk_it =
          chunks.erase(begin(false).chunk_it, masked_start.chunk_it);
      masked_start.chunk() = masked_start.chunk().slice(masked_start.chunk_off);
      masked_start.chunk_off = 0; // truncate the current chunk from the head
      insert_pos = begin(false);
    }
    _size -= erased_size;
    mask_off -= erased_size;

    // allocate and insert the new contiguous chunk
    masked_start.chunk_it = chunks.emplace(insert_pos.chunk_it, res_size) + 1;
    _size += res_size;
    mask_off += res_size;
  }

  void mask(size_t mask_size) {
    assert(mask_off + mask_size <= _size);
    masked_start += mask_size;
    mask_off += mask_size;
  }

  void unmask(size_t unmask_size) {
    assert(unmask_size <= mask_off);
    masked_start -= unmask_size;
    mask_off -= unmask_size;
  }

  /// Return the current size of the unmasked part
  size_t size() const { return _size - mask_off; }

  enum class InsertError { OVERLAPPING_LEFT, OVERLAPPING_RIGHT };

  /// Insert a chunk into the buffer at `offset` given relative
  /// to the currently unmasked part. On success, returns an [Iterator] pointing
  /// to the newly inserted chunk.
  ///
  /// The chunk at the offset must be a hole of length greater or equal to the
  /// length of the inserted chunk. If the chunk at the offset is not a hole,
  /// [InsertError::OVERLAPPING_LEFT] is returned. If the length of the hole is
  /// less than the length of the inserted chunk,
  /// [InsertError::OVERLAPPING_RIGHT] is returned.
  Result<iterator, InsertError> insert_chunk(const BufChunk &chunk,
                                             size_t offset) {
    if (offset >= size()) {
      // we expect to find a hole at the offset, so create one if we are
      // inserting beyond the end of the buffer
      size_t end_hole_size = offset + chunk.size() - size();
      chunks.emplace_back(BufChunk::empty(end_hole_size));
      _size += end_hole_size;
      n_holes += 1;
    }

    auto insert_hole_it = masked_start + offset;
    if (!insert_hole_it.is_hole())
      return ResultError(InsertError::OVERLAPPING_LEFT);
    size_t insert_hole_size = insert_hole_it.chunk().size();
    size_t left_hole_size = insert_hole_it.chunk_off;
    ssize_t right_hole_size =
        insert_hole_size - (left_hole_size + chunk.size());
    if (right_hole_size < 0)
      return ResultError(InsertError::OVERLAPPING_RIGHT);

    insert_hole_it.chunk_off = 0;
    if ((left_hole_size == 0) &&
        (right_hole_size > 0)) { // left-aligned insertion
      chunks.emplace(insert_hole_it.chunk_it + 1,
                     BufChunk::empty(right_hole_size));
      insert_hole_it.chunk() = chunk;
    } else if ((left_hole_size > 0) &&
               (right_hole_size == 0)) { // right-aligned insertion
      chunks.emplace(insert_hole_it.chunk_it + 1, chunk);
      insert_hole_it.chunk() = BufChunk::empty(left_hole_size);
      insert_hole_it = insert_hole_it.next_chunk();
    } else if ((left_hole_size == 0) &&
               (right_hole_size == 0)) { // full-aligned insertion
      insert_hole_it.chunk() = chunk;
      n_holes -= 1;
    } else { // strictly-inside-hole insertion
      chunks.emplace(insert_hole_it.chunk_it + 1,
                     BufChunk::empty(right_hole_size));
      auto new_left_hole_it = chunks.emplace(insert_hole_it.chunk_it,
                                             BufChunk::empty(left_hole_size));
      insert_hole_it.chunk_it = new_left_hole_it + 1;
      insert_hole_it.chunk() = chunk;
      n_holes += 1;
    }

    masked_start = insert_hole_it - offset;
    return insert_hole_it;
  }

  /// Insert a [Buf] into the buffer at `offset` given relative to the currently
  /// unmasked part.
  ///
  /// Only the unmasked part of `other_buf` is inserted. The insertion is
  /// performed by repeatedly calling [insert_chunk].
  Result<iterator, InsertError> insert(Buf &other_buf, size_t offset,
                                       size_t length = std::dynamic_extent) {
    auto chunk_it = other_buf.begin();
    size_t inserted_size = offset;
    Iterator result_it = begin() + std::min(size(), offset);
    // TODO: do not make [insert_chunk] recompute the insertion iterator on each
    // call
    while ((chunk_it != other_buf.end()) && (inserted_size < length)) {
      BufChunk chunk = chunk_it.sliced_chunk();
      if (chunk.size() == 0) {
        chunk_it = chunk_it.next_chunk();
        continue;
      }
      if (chunk.size() + inserted_size > length)
        chunk = chunk.slice(0, length - inserted_size);
      auto insert_res = insert_chunk(chunk, inserted_size);
      if (insert_res.has_error())
        return insert_res;
      if (chunk_it == other_buf.begin())
        result_it = insert_res.value();
      inserted_size += chunk.size();
      chunk_it = chunk_it.next_chunk();
    }
    return result_it;
  }

  iterator begin(bool masked = true) {
    if (masked)
      return masked_start;
    else
      return {chunks.begin(), 0};
  }
  iterator end() {
    return {chunks.end(), 0};
  }

  const_iterator begin(bool masked = true) const {
    if (masked)
      return masked_start;
    else
      return {chunks.begin(), 0};
  }
  const_iterator end() const { 
    return {chunks.end(), 0};
  }

  bool is_contiguous() const { return chunks.size() == 1; }
  bool is_complete() const { return n_holes == 0; }

  /// Create a contiguous (single-chunk) version of the unmasked part of the
  /// buffer. May allocate a new contiguous backing [BufChunk]. Does not
  /// guarantee to keep the masked part of the buffer.
  Buf as_contiguous() const {
    if (is_contiguous())
      return *this;
    Buf contig_buf(size());
    std::ranges::copy(*this, contig_buf.begin());
    return contig_buf;
  }

  /// Truncate the unmasked part of the buffer.
  void truncate(size_t new_size) {
    if (new_size >= size())
      return;
    if (new_size == 0) {
      masked_start.chunk_it = chunks.erase(masked_start.chunk_it, chunks.end());
      masked_start.chunk_off = 0;
      _size = mask_off;
      return;
    }
    auto end_it = begin() + new_size;
    for (auto it = end_it.next_chunk(); it != end(); it++) {
      if (it.is_hole())
        n_holes -= 1;
    }
    chunks.erase(end_it.chunk_it + 1, chunks.end());
    end_it.chunk() = end_it.chunk().slice(0, end_it.chunk_off);
    if (end_it.chunk().size() == 0)
      chunks.erase(end_it.chunk_it, end_it.chunk_it + 1);
    _size = new_size + mask_off;
  }
};
} // namespace jay
