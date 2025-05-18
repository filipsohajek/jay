#pragma once
#include <chrono>
#include <functional>
#include <queue>

namespace jay {
using clock = std::chrono::steady_clock;

class TimerQueue;
class Timer {
  friend class TimerQueue;
  friend struct std::greater<Timer>;

public:
  Timer(clock::duration duration, std::function<void(Timer *)> callback,
        TimerQueue &queue)
      : expiry(clock::now() + duration), duration(duration),
        callback(std::move(callback)), active(true), queue(queue) {}

  ~Timer();

  void reset();

private:
  clock::time_point expiry;
  clock::duration duration;
  std::function<void(Timer *)> callback;

  bool active;
  TimerQueue &queue;

  void invoke() {
    callback(this);
    active = false;
  }
};
} // namespace jay

namespace std {
template <> struct greater<jay::Timer> {
  bool operator()(const jay::Timer &lhs, const jay::Timer &rhs) {
    return lhs.expiry > rhs.expiry;
  }
};
}; // namespace std

namespace jay {
class TimerQueue : std::priority_queue<Timer *, std::vector<Timer *>,
                                       std::greater<Timer *>> {
public:
  void poll() {
    clock::time_point now = clock::now();
    while (!empty() && (top()->expiry < now)) {
      Timer *timer = top();
      pop();
      timer->active = false;
      timer->callback(timer);
    }
  }

  void reset(Timer *timer) {
    timer->expiry = clock::now() + timer->duration;
    if (timer->active) {
      std::make_heap(c.begin(), c.end(), comp);
    } else {
      push(timer);
      timer->active = true;
    }
  }

  void remove(Timer &timer) {
    timer.active = false;
    auto it = std::find(c.begin(), c.end(), &timer);
    c.erase(it);
    std::make_heap(c.begin(), c.end(), comp);
  }

  [[nodiscard]] std::unique_ptr<Timer>
  create(clock::duration duration, std::function<void(Timer *)> callback) {
    auto timer = std::make_unique<Timer>(duration, std::move(callback), *this);
    push(timer.get());
    return timer;
  }
};

inline Timer::~Timer() {
  if (active)
    queue.remove(*this);
}

inline void Timer::reset() { queue.reset(this); }

class WithTimers {
public:
  void poll_timers() { timers.poll(); }

protected:
  TimerQueue timers;
};
} // namespace jay
