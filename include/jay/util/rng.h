#pragma once
#include <random>

namespace jay {
static thread_local std::mt19937_64 rng {std::random_device()()};

template<typename Ti1, typename Ti2>
auto random_int(Ti1 min = std::numeric_limits<Ti1>::min(), Ti2 max = std::numeric_limits<Ti2>::max()) {
  return std::uniform_int_distribution<std::conditional_t<sizeof(Ti1) >= sizeof(Ti2), Ti1, Ti2>>(min, max)(rng);
}
};
