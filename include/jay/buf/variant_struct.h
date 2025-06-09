#pragma once

#include "jay/buf/struct.h"
#include <cstddef>
#include <optional>
#include <utility>
#include <variant>

namespace jay {
/// A helper class for creating joint structs, which are themselves subclasses
/// of [std::variant] and dynamically dispatch field accesses to the currently
/// set variant.
struct JointStruct {
  template <typename Tr, typename... FieldTs> struct VariantField {
    using FieldVariant = std::variant<FieldTs...>;
    using FieldTypeVariant = std::variant<RemoveField_t<FieldTs>...>;
    using Type = Tr;

    explicit VariantField(FieldVariant field_var) : field_var(field_var) {}
    operator Tr() const {
      return convert(std::make_index_sequence<sizeof...(FieldTs)>());
    }
    template <size_t... I> void operator=(const Tr &var) const {
      assign(var, std::make_index_sequence<sizeof...(FieldTs)>());
    }

  private:
    template <size_t... I> Tr convert(std::index_sequence<I...>) const {
      std::optional<Tr> result;

      (
          [&]() {
            if (field_var.index() == I)
              result = Tr(std::get<I>(field_var).value());
          }(),
          ...);

      return result.value();
    }

    template <size_t... I>
    void assign(const Tr &var, std::index_sequence<I...>) const {
      (
          [&]() {
            if (field_var.index() == I)
              std::get<I>(field_var) = var;
          }(),
          ...);
    }

    FieldVariant field_var;
  };

  template <typename Tr, typename... FieldTs>
  static VariantField<Tr, FieldTs...>
  make_variant_field(std::variant<FieldTs...> field_var) {
    return VariantField<Tr, FieldTs...>{field_var};
  }
};

#define JOINT_FIELD(name, type)                                                \
  template <typename... StructTs>                                              \
  auto _##name##_field(const std::variant<StructTs...> *struct_var) const {    \
    return [&]<size_t... I>(std::index_sequence<I...>) {                       \
      std::optional<std::variant<                                              \
          std::invoke_result_t<decltype(&StructTs::name), StructTs *>...>>     \
          field_var;                                                           \
      [[maybe_unused]] void *dummy[sizeof...(I)] = {                           \
          ((struct_var->index() == I)                                          \
               ? (field_var.emplace(std::in_place_index<I>,                    \
                                    std::get<I>(*struct_var).name()),          \
                  nullptr)                                                     \
               : nullptr)...};                                                 \
      return make_variant_field<type>(field_var.value());                      \
    }(std::make_index_sequence<sizeof...(StructTs)>());                        \
  }                                                                            \
  template <typename... StructTs> auto name() const {                          \
    return _##name##_field(this);                                              \
  }

} // namespace jay
