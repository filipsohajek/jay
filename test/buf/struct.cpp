#include "jay/buf/struct.h"
#include "jay/buf/variant_struct.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_range_equals.hpp>
#include <format>

template <typename T>
void test_buf_nbo_rw(T val, std::array<uint8_t, sizeof(T)> expected_nbo,
                     std::array<uint8_t, sizeof(T)> expected_le,
                     const char *name) {
  std::vector<uint8_t> buf(sizeof(T));

  jay::StructWriter cur_nbo(buf);
  cur_nbo.write(0, val, true);
  UNSCOPED_INFO(std::format("{} NBO write expected output", name));
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals(expected_nbo));
  cur_nbo = jay::StructWriter{buf};
  UNSCOPED_INFO(std::format("{} NBO write readback", name));
  REQUIRE(cur_nbo.read<T>(0, true) == val);

  jay::StructWriter cur_hbo(buf);
  cur_hbo.write(0, val, false);
  UNSCOPED_INFO(std::format("{} HBO write expected output", name));
#if NATIVE_IS_NETWORK
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals(expected_nbo));
#else
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals(expected_le));
#endif
  cur_hbo = jay::StructWriter{buf};
  UNSCOPED_INFO(std::format("{} HBO write readback", name));
  REQUIRE(cur_hbo.read<T>(0, false) == val);
}

TEST_CASE("BufCursor network byte order is respected", "[buf]") {
  uint32_t in_uint32 = 0x13579bdf;
  uint16_t in_uint16 = 0x369c;
  uint8_t in_uint8 = 0xcd;

  test_buf_nbo_rw(in_uint32, {0x13, 0x57, 0x9b, 0xdf}, {0xdf, 0x9b, 0x57, 0x13},
                  "uint32");
  test_buf_nbo_rw(in_uint16, {0x36, 0x9c}, {0x9c, 0x36}, "uint16");
  test_buf_nbo_rw(in_uint8, {0xcd}, {0xcd}, "uint8");

  std::array<uint32_t, 2> in_u32_arr{0x13579bdf, 0x2468ace0};
  test_buf_nbo_rw(in_u32_arr, {0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0},
                  {0xdf, 0x9b, 0x57, 0x13, 0xe0, 0xac, 0x68, 0x24},
                  "uint32 array");
};

struct TestStruct : public jay::BufStruct<TestStruct> {
  using ::TestStruct::BufStruct::BufStruct;
  STRUCT_FIELD(u8_field, 0, uint8_t);
  STRUCT_FIELD(u16_field, 1, uint16_t);
  STRUCT_FIELD(u32_field, 3, uint32_t);

  size_t size() const { return 7; }
};
struct TestStruct2 : public jay::BufStruct<TestStruct2> {
  using ::TestStruct2::BufStruct::BufStruct;
  STRUCT_FIELD(u8_field, 1, uint8_t);
  STRUCT_FIELD(u16_field, 2, uint16_t);
  STRUCT_FIELD(u32_field, 4, uint32_t);
  size_t size() const { return 8; }
};
struct TestVariant : public std::variant<TestStruct, TestStruct2>, jay::JointStruct {
  using std::variant<TestStruct, TestStruct2>::variant;
  JOINT_FIELD(u8_field, uint8_t);
  JOINT_FIELD(u16_field, uint16_t);
  JOINT_FIELD(u32_field, uint32_t);
};

TEST_CASE("BufStruct fields get written and read correctly", "[buf]") {
  std::vector<uint8_t> buf(7);
  jay::StructWriter cur{buf};
  TestStruct ts = TestStruct::construct(cur).value();
  ts.u8_field() = 0x12;
  ts.u16_field() = 0x1234;
  ts.u32_field() = 0x12345678;
  REQUIRE(ts.u8_field() == 0x12);
  REQUIRE(ts.u16_field() == 0x1234);
  REQUIRE(ts.u32_field() == 0x12345678);
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals({0x12, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78}));
}

TEST_CASE("JointStruct discriminates correctly", "[buf]") {
  std::vector<uint8_t> buf(8);
  jay::StructWriter cur{buf};
  TestVariant var = TestStruct::construct(cur).value();
  var.u8_field() = 0x1;
  var.u16_field() = 0x0203;
  var.u32_field() = 0x04050607;
  REQUIRE(var.u8_field() == 0x01);
  REQUIRE(var.u16_field() == 0x0203);
  REQUIRE(var.u32_field() == 0x04050607);
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00}));

  var = TestStruct2::construct(cur).value();
  var.u8_field() = 0x1;
  var.u16_field() = 0x0203;
  var.u32_field() = 0x04050607;
  REQUIRE(var.u8_field() == 0x01);
  REQUIRE(var.u16_field() == 0x0203);
  REQUIRE(var.u32_field() == 0x04050607);
  REQUIRE_THAT(buf, Catch::Matchers::RangeEquals({0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}));
}

