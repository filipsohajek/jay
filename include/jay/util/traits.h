#pragma once

#include <cstddef>
#include <utility>
#include <variant>
namespace jay {

template <typename T>
concept IsSubscriptable = requires(T t) {
  { t[size_t()] };
};

template <typename T>
struct RemoveExtent
    : public std::remove_reference<decltype(std::declval<T>()[size_t()])> {};
template <typename T> using RemoveExtent_t = typename RemoveExtent<T>::type;

/// Trait for matching array-like types -- types that are subscriptable with
/// result type `Tr` and layout-compatible with `Tr[sizeof(T)/sizeof(Tr)]`. Used
/// for matching "safely"-serializable subclasses of std::array.
template <IsSubscriptable T>
struct IsArrayLike
    : std::disjunction<
          std::is_array<T>,
          std::is_layout_compatible<
              T, std::array<RemoveExtent_t<T>,
                            sizeof(T) / sizeof(RemoveExtent_t<T>)>>> {};
template <typename T> constexpr bool IsArrayLike_v = IsArrayLike<T>::value;

template <typename> constexpr bool DependentFalse_v = false;

template <typename Ti, typename... Tivar> struct IsVariantAlternative;
template <typename Ti, typename... Tivar>
struct IsVariantAlternative<Ti, std::variant<Tivar...>>
    : std::disjunction<std::is_same<Ti, Tivar>...> {};

} // namespace jay
