#include "jay/buf/sbuf.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_range_equals.hpp>

TEST_CASE("sbuf", "[sbuf]") {
  jay::Buf buf(10);
  buf.reserve_before(15);
  buf.unmask(10);
  buf.reserve_before(10);
  std::fill(buf.begin(), buf.end(), 'A');

  jay::Buf buf2(10);
  buf2.mask(2);
  std::fill(buf2.begin(), buf2.end(), 'B');

  jay::Buf buf3(10);
  std::fill(buf3.begin(), buf3.end(), 'C');

  buf.insert(buf2, 25);
  buf3.mask(5);
  buf.insert(buf3, 20);

  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals({'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'C', 'C', 'C', 'C', 'C', 'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B'}));
  buf.truncate(28);
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals({'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'C', 'C', 'C', 'C', 'C', 'B', 'B', 'B'}));
  buf.truncate(8);
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals({'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'}));
  buf.truncate(0);
  REQUIRE(buf.size() == 0);
  buf.unmask(5);
  std::fill(buf.begin(), buf.end(), 'X');
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals({'X', 'X', 'X', 'X', 'X'}));
}
