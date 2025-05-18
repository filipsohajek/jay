#include "jay/util/smallvec.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_range_equals.hpp>

TEST_CASE("smallvec", "[smallvec]") {
  jay::SmallVec<size_t, 4> vec;
  for (size_t i = 0; i < 10; i++) {
    vec.emplace_back(i);
  }
  REQUIRE_THAT(vec, Catch::Matchers::RangeEquals({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
  auto it = vec.begin();
  for (size_t i = 0; i < 5; i++) {
    it = vec.erase(it);
    it++;
  }

  REQUIRE_THAT(vec, Catch::Matchers::RangeEquals({1, 3, 5, 7, 9}));
}
