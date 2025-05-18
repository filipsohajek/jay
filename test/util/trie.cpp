#include "jay/util/trie.h"
#include "jay/ip/common.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_range_equals.hpp>
#include <ranges>

TEST_CASE("trie", "[trie]") {
  jay::BitTrie<jay::ip::IPv4Addr, uint32_t> trie;
  trie.emplace({0, 0, 0, 0}, 0, 4);
  trie.emplace({10, 0, 0, 0}, 8, 5);
  trie.emplace({192, 0, 0, 0}, 8, 0);
  trie.emplace({192, 168, 0, 0}, 16, 1);
  trie.emplace({192, 168, 1, 0}, 24, 2);
  trie.emplace({192, 168, 2, 0}, 24, 3);
  trie.emplace({192, 168, 2, 0}, 24, 6);
  trie.emplace({192, 168, 2, 128}, 32, 6);
  
  trie.erase({192, 168, 2, 0}, 24);
  trie.erase({0, 0, 0, 0}, 0);

  std::pair<jay::ip::IPv4Addr, uint32_t> expected[] = {
    {{10, 0, 0, 0}, 5},
    {{192, 0, 0, 0}, 0},
    {{192, 168, 1, 0}, 2},
    {{192, 168, 2, 128}, 6},
    {{192, 168, 0, 0}, 1}
  };
  REQUIRE_THAT(std::ranges::views::all(trie) | std::views::transform([](const auto& pair) {
    return std::make_pair(pair.first, *pair.second);
  }), Catch::Matchers::RangeEquals(expected));
}
