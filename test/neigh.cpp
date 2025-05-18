#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_tostring.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <thread>

#include "jay/eth.h"
#include "jay/ip/common.h"
#include "jay/neigh.h"
#include "jay/pbuf.h"

CATCH_REGISTER_ENUM(jay::NeighState, jay::NeighState::INCOMPLETE,
                    jay::NeighState::REACHABLE, jay::NeighState::STALE,
                    jay::NeighState::DELAY, jay::NeighState::PROBE);
TEST_CASE("NeighCache initial resolution", "[neighbour]") {
  using enum jay::NeighState;
  jay::NeighCache ncache;
  ncache.reachable_timeout = std::chrono::milliseconds(100);
  ncache.delay_timeout = std::chrono::milliseconds(100);
  ncache.retrans_timeout = std::chrono::milliseconds(100);
  std::optional<
      std::tuple<jay::Interface *, jay::ip::IPAddr, std::optional<jay::HWAddr>,
                 std::optional<jay::ip::IPAddr>>>
      last_sol;
  std::optional<jay::ip::IPAddr> last_unreach;
  ncache.set_callbacks(
      [&last_sol](auto iface, auto tgt_iaddr, auto hwaddr, auto src_iaddr) {
        last_sol = std::make_tuple(iface, tgt_iaddr, hwaddr, src_iaddr);
      },
      [&last_unreach](jay::ip::IPAddr ip, jay::Neighbour &) { last_unreach = ip; });

  jay::ip::IPAddr nh_iaddr = jay::ip::IPv4Addr{0x1, 0x2, 0x3, 0x4};
  jay::HWAddr nh_haddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  jay::HWAddr nh_haddr2{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  jay::ip::IPAddr src_addr = jay::ip::IPv4Addr{0x5, 0x6, 0x7, 0x8};
  jay::PBuf packet;
  packet->reserve_headers();
  packet->construct_net_hdr<jay::ip::IPHeader>(jay::ip::IPVersion::V4).value().src_addr() = src_addr;
  packet->nh_iaddr = nh_iaddr;

  REQUIRE(!ncache.resolve(std::move(packet)).has_value());
  const jay::Neighbour *neigh = ncache.at(nh_iaddr);

  SECTION("transitions from INCOMPLETE") {
    SECTION("timeout") {
      REQUIRE(neigh != nullptr);
      for (size_t retry_i = 0; retry_i < ncache.max_query_retries; retry_i++) {
        REQUIRE(neigh->state == INCOMPLETE);
        REQUIRE(last_sol.has_value());
        REQUIRE(!last_unreach.has_value());
        auto [ifa, ip, hwa, sip] = last_sol.value();

        INFO("solicitation: tgt_iaddr="
             << ip.v4() << ", thaddr_hint=" << hwa.value_or(jay::HWAddr{})
             << ", siaddr_hint=" << sip.value_or(jay::ip::IPAddr{}).v4() << "\n");
        REQUIRE(last_sol ==
                std::make_tuple(nullptr, nh_iaddr, std::nullopt, src_addr));
        last_sol.reset();
        std::this_thread::sleep_for(ncache.retrans_timeout);
        ncache.poll_timers();
      }
      REQUIRE(last_unreach == nh_iaddr);
    }

    SECTION("INCOMPLETE w/ unsolicited NA") {
      auto queued = ncache.process_adv(nh_iaddr, nh_haddr,
                                       {.is_adv = true, .solicited = false});
      REQUIRE(queued != std::nullopt);
      REQUIRE(queued.value().size() == 1);
      REQUIRE(neigh->state == STALE);
    }

    SECTION("INCOMPLETE w/ solicited NA") {
      auto queued = ncache.process_adv(nh_iaddr, nh_haddr,
                                       {.is_adv = true, .solicited = true});
      REQUIRE(queued != std::nullopt);
      REQUIRE(queued.value().size() == 1);
      REQUIRE(neigh->state == REACHABLE);
    }

    SECTION("INCOMPLETE w/ empty NA") {
      REQUIRE(!neigh->router);
      auto queued = ncache.process_adv(nh_iaddr, std::nullopt,
                                       {.is_adv = true, .router = true});
      REQUIRE(neigh->router);
      REQUIRE(queued == std::nullopt);
      REQUIRE(neigh->state == INCOMPLETE);
    }
  }

  SECTION("transitions of complete entries") {
    std::ignore = ncache.process_adv(nh_iaddr, nh_haddr,
                                     {.is_adv = true, .solicited = true});
  jay::PBuf packet2;
  packet2->reserve_headers();
  packet2->construct_net_hdr<jay::ip::IPHeader>(jay::ip::IPVersion::V4).value().src_addr() = src_addr;
  packet2->nh_iaddr = nh_iaddr;


    SECTION("REACHABLE -> STALE -> DELAY") {
      REQUIRE(neigh->state == REACHABLE);
      std::this_thread::sleep_for(ncache.reachable_timeout);
      ncache.poll_timers();
      REQUIRE(neigh->state == STALE);
      std::ignore = ncache.resolve(std::move(packet2));
      REQUIRE(neigh->state == DELAY);
      SECTION("DELAY -> PROBE (unreachable)") {
        std::this_thread::sleep_for(ncache.delay_timeout);
        ncache.poll_timers();
        REQUIRE(neigh->state == PROBE);
        REQUIRE(last_sol ==
                std::make_tuple(nullptr, nh_iaddr, nh_haddr, src_addr));
        for (size_t retry_i = 0; retry_i < ncache.max_query_retries;
             retry_i++) {
          std::this_thread::sleep_for(ncache.retrans_timeout);
          ncache.poll_timers();
        }
        REQUIRE(ncache.at(nh_iaddr) == nullptr);
      }
      SECTION("DELAY -> REACHABLE (external hint)") {
        ncache.notify_reachable(nh_iaddr);
        REQUIRE(neigh->state == REACHABLE);
      }
    }

    SECTION("common transitions") {
      jay::NeighState src_state = GENERATE(REACHABLE, STALE, PROBE, DELAY);
      if (src_state != REACHABLE) {
        std::this_thread::sleep_for(ncache.reachable_timeout);
        ncache.poll_timers();
        if (src_state != STALE) {
          std::ignore = ncache.resolve(std::move(packet2));
          if (src_state != DELAY) {
            std::this_thread::sleep_for(ncache.delay_timeout);
            ncache.poll_timers();
          }
        }
      }
      REQUIRE(neigh->state == src_state);
      CAPTURE(src_state);

      SECTION("NA receipt") {
        auto [solicited, override, new_haddr, res_state, res_haddr,
              update_router] =
            GENERATE_COPY(table<bool, bool, std::optional<jay::HWAddr>,
                                jay::NeighState, jay::HWAddr, bool>({
                          // Solicited=1, Override=0, Same link-layer address as cached
                          {true, false, nh_haddr, REACHABLE, nh_haddr, true},
                          // Solicited=any, Override=any, No link-layer address
                          {false, false, std::nullopt, src_state, nh_haddr, true},
                          {false, true, std::nullopt, src_state, nh_haddr, true},
                          {true, false, std::nullopt, REACHABLE, nh_haddr, true},
                          {true, true, std::nullopt, REACHABLE, nh_haddr, true},
                          // Solicited=1, Override=0, Different link-layer address than cached
                          {true, false, nh_haddr2, (src_state == REACHABLE) ? STALE : src_state, nh_haddr, false},
                          // Solicited=1, Override=1
                          {true, true, nh_haddr2, REACHABLE, nh_haddr2, true},
                          // Solicited=0, Override=0
                          {false, false, nh_haddr2, (src_state == REACHABLE) ? STALE : src_state, nh_haddr, false},
                          {false, false, nh_haddr, src_state, nh_haddr, true},
                          // Solicited=0, Override=1, Same link-layer address as cached
                          {false, true, nh_haddr, src_state, nh_haddr, true},
                          // Solicited=0, Override=1, Different link-layer address than cached
                          {false, true, nh_haddr2, STALE, nh_haddr2, true}
                          }));

        CAPTURE(solicited);
        CAPTURE(override);
        bool has_haddr = new_haddr.has_value();
        bool haddr_differs = (new_haddr != neigh->haddr);
        INFO((has_haddr ? std::format("haddr_differs := {}", haddr_differs) : "has_haddr := false" ));

        std::ignore = ncache.process_adv(
            nh_iaddr, new_haddr,
            {.is_adv = true, .router = true, .solicited = solicited, .override = override});
        REQUIRE(neigh->state == res_state);
        bool router_updated = neigh->router;
        REQUIRE(update_router == router_updated);
        bool res_haddr_correct = (neigh->haddr == res_haddr);
        REQUIRE(res_haddr_correct);
      }
      SECTION("upper-layer reachability confirmation") {
        ncache.notify_reachable(nh_iaddr);
        REQUIRE(neigh->state == REACHABLE);
      }
    }
  }
}
