#pragma once
#include <utility>
#include <variant>
namespace jay {
template <typename TError> class ResultError {
  TError _error;

public:
  TError &&error() && { return _error; }
  TError &error() & { return _error; }
  ResultError(const TError &err) : _error(err) {}
  ResultError(TError &&err) : _error(err) {}
  ResultError(const ResultError &) = default;
  ResultError(ResultError &&) = default;

  template <typename... Args>
  ResultError(Args &&...args) : _error(std::forward<TError>(args)...) {}
};
template <typename TValue, typename TError> class Result {
public:
  Result() : res(TValue()) {};
  Result(const Result &) = default;
  Result(Result &&) = default;

  template <typename... Args>
  Result(Args &&...args)
      : res(std::in_place_type_t<TValue>(), std::forward<Args>(args)...) {}
  template <typename TOValue, typename TOError>
  Result(const Result<TOValue, TOError> &other_res) : res(std::monostate()) {
    if (other_res.has_error())
      res = TError(other_res.error());
    else
      res = TValue(other_res.value());
  }

  template <typename TOValue, typename TOError>
  Result(Result<TOValue, TOError> &&other_res) : res(std::monostate()) {
    if (other_res.has_error())
      res = TError(other_res.error());
    else
      res = TValue(other_res.value());
  }

  Result(TValue &&val) : res(std::forward<TValue>(val)) {}
  Result(ResultError<TError> err) : res(err.error()) {}

  bool has_value() const { return std::holds_alternative<TValue>(res); }

  bool has_error() const { return std::holds_alternative<TError>(res); }

  template <typename F> auto transform(F &&f) const {
    using ResType =
        std::remove_cv_t<std::invoke_result_t<F, decltype(value())>>;
    return has_value() ? Result<ResType, TError>(f(value()))
                       : Result<ResType, TError>(ResultError<TError>(error()));
  }

  template <typename Tr> Tr value_or(Tr &&default_val) {
    return has_value() ? static_cast<Tr>(value()) : default_val;
  }

  const TError &error() const { return std::get<TError>(res); }
  const TValue &value() const { return std::get<TValue>(res); }

private:
  std::variant<std::monostate, TValue, TError> res;
};

#define UNWRAP_RETURN(result) ({auto _res = result; if (_res.has_error()) return; _res.value();})
#define UNWRAP_RETURN_ERR(result, err) ({auto _res = result; if (_res.has_error()) return ResultError(err); _res.value();})
#define UNWRAP_PROPAGATE(result) ({auto _res = result; if (_res.has_error()) return ResultError(_res.error()); _res.value();})
}; // namespace jay
