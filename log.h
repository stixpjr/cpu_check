#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <atomic>
#include <iostream>
#include <sstream>
#include <string>

enum LOG_LEVEL {
  DEBUG,
  INFO,
  WARN,
  ERROR,
  FATAL,
};

// TODO - Flag to filter above a given log level

// TODO
// Make this more efficient. Eg. use sneaky hack like:
//   LOG_IF_COND(xx) << yy;
// becomes
//   for (condvar;COND;) Log(blah).stream() << yy;

#define LOG(X) Log(__FILE__, __LINE__, X).stream()

#define LOG_EVERY_N(X, N)                                       \
  static std::atomic<uint64_t> __FILE__##__LINE__##_counter(0); \
  Log(__FILE__, __LINE__, X, __FILE__##__LINE__##_counter, N).stream()

#define LOG_EVERY_N_SECS(X, N)                                  \
  static std::atomic<int64_t> __FILE__##__LINE__##_lasttime(0); \
  Log(__FILE__, __LINE__, X, __FILE__##__LINE__##_lasttime, N).stream()

// TODO
// #define VLOG(x)

static LOG_LEVEL min_log_level = INFO;

class Log {
 public:
  Log(const char* file, int line, LOG_LEVEL lvl) : lvl_(lvl) {
    if (lvl < min_log_level) {
      skip_ = true;
      return;
    }
    Init(file, line);
  }
  // For LOG_EVERY_N:
  Log(const char* file, int line, LOG_LEVEL lvl, std::atomic<uint64_t>& cnt,
      int N)
      : lvl_(lvl) {
    if (lvl < min_log_level) {
      skip_ = true;
      return;
    }
    if ((++cnt % N) != 0) {
      skip_ = true;
      return;
    }
    Init(file, line);
  }
  // For LOG_EVERY_N_SECS:
  Log(const char* file, int line, LOG_LEVEL lvl, std::atomic<int64_t>& t, int N)
      : lvl_(lvl) {
    if (lvl < min_log_level) {
      skip_ = true;
      return;
    }
    int64_t now = time(nullptr);
    int64_t last = t;

    if (now - last < N || !t.compare_exchange_strong(last, now)) {
      skip_ = true;
      return;
    }
    Init(file, line);
  }

  ~Log() {
    if (skip_) return;
    os_ << std::endl;
    (lvl_ < WARN ? std::cerr : std::cout) << os_.str();
    if (lvl_ == FATAL) {
      abort();
    }
  }

  std::ostream& stream() { return os_; }

  std::ostream& operator<<(const std::string& s) {
    if (skip_) return os_;
    return os_ << s;
  }

 private:
  void Init(const char* file, int line) {
    static const char l[] = {
        'D', 'I', 'W', 'E', 'F',
    };
    struct timeval tvs;
    struct tm tms;
    time_t t;
    char s[17];
    gettimeofday(&tvs, nullptr);
    t = tvs.tv_sec;
    gmtime_r(&t, &tms);
    strftime(s, sizeof(s), "%Y%m%d-%H%M%S.", &tms);
    char us[7];
    snprintf(us, sizeof(us), "%06ld", (long)tvs.tv_usec);

    os_ << l[lvl_] << s << us << ' ' << pthread_self() << " " << file << ':'
        << line << "] ";
  }

  LOG_LEVEL lvl_;
  bool skip_ = false;
  std::stringstream os_;
};
