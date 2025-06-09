#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_range_equals.hpp>
#include <iostream>
#include <ranges>

#include "jay/ip/v4.h"
#include "jay/ip/common.h"

TEST_CASE("IPv4 header (de)serialization", "[ipv4]") {
  std::vector<uint8_t> buf(jay::ip::IPv4Header::MIN_SIZE);
  jay::StructWriter cur{buf};
  jay::ip::IPv4Header hdr = jay::ip::IPv4Header::construct(cur, jay::ip::IPProto::UDP).value();
  hdr.dscp() = 4;
  hdr.ecn() = 1;
  jay::ip::IPv4FragData frag_data = hdr.frag_data().construct().value();
  frag_data.identification() = 0x33cb;
  frag_data.dont_frag() = false;
  frag_data.more_frags() = true;
  frag_data.frag_offset() = 1480;
  
  hdr.ttl() = 128;
  hdr.src_addr() = jay::ip::IPv4Addr {192, 168, 1, 10};
  hdr.dst_addr() = jay::ip::IPv4Addr {192, 168, 1, 1};
  hdr.total_len() = 20;
  hdr.hdr_csum() = jay::ip::inet_csum(hdr.cursor().span());

  REQUIRE_THAT(buf | std::views::transform([](uint8_t byte) {return static_cast<uint32_t>(byte); }), Catch::Matchers::RangeEquals({0x45, 0x11, 0x00, 0x14, 0x33, 0xcb, 0x20, 0xb9, 0x80, 0x11, 0x62, 0xe8, 0xc0, 0xa8, 0x01, 0x0a, 0xc0, 0xa8, 0x01, 0x01}));

  hdr = jay::ip::IPv4Header::read(cur).value();
  REQUIRE(hdr.dscp() == 4);
  REQUIRE(hdr.ecn() == 1);
  frag_data = hdr.frag_data().read().value();
  REQUIRE(frag_data.identification() == 0x33cb);
  REQUIRE(!frag_data.dont_frag());
  REQUIRE(frag_data.more_frags());
  REQUIRE(frag_data.frag_offset() == 1480);
  REQUIRE(hdr.ttl() == 128);
  REQUIRE(hdr.proto() == jay::ip::IPProto::UDP);
  REQUIRE(jay::ip::IPv4Addr(hdr.src_addr()) == jay::ip::IPv4Addr {192, 168, 1, 10});
  REQUIRE(jay::ip::IPv4Addr(hdr.dst_addr()) == jay::ip::IPv4Addr {192, 168, 1, 1});
}
