#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <algorithm>
#include <atomic>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/evp.h>

#include "config.h"

#include "crc32c.h"
#include "farmhash.h"

#include "log.h"

const int BUF_MIN = 100;      // 100 bytes
const int BUF_MAX = 1 << 20;  // 1 MiB

#if defined(__i386__) || defined(__x86_64__)
inline void __movsb(char *dst, const char *src, size_t size) {
  __asm__ __volatile__("rep movsb"
                       : "+D"(dst), "+S"(src), "+c"(size)
                       :
                       : "memory");
}
#endif

std::string HexData(const char *s, uint32_t l) {
  const char d[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string o;
  o.resize(l << 1);
  for (uint32_t i = 0; i < l; i++) {
    uint8_t b = s[i];
    o[(i << 1)] = d[(b >> 4) & 0xf];
    o[(i << 1) + 1] = d[b & 0xf];
  }
  return o;
}

std::string HexStr(const std::string &s) { return HexData(s.data(), s.size()); }

std::atomic_bool exiting(false);
std::atomic_uintmax_t errorCount(0);
std::atomic_uintmax_t successCount(0);

bool SetAffinity(int id) {
  int err = 0;
#ifdef __linux__
  cpu_set_t cset;
  CPU_ZERO(&cset);
  CPU_SET(id, &cset);
  err = sched_setaffinity(0, sizeof(cset), &cset);
  std::atomic_thread_fence(std::memory_order_seq_cst);
  if (err) {
    err = errno;
  }
#elif defined(__NetBSD__)
  cpuset_t *cset;
  cset = cpuset_create();
  if (cset == nullptr) {
    LOG(ERROR) << "cpuset_create failed: " << strerror(errno);
    return false;
  }
  cpuset_set(id, cset);
  err = pthread_setaffinity_np(pthread_self(), cpuset_size(cset), cset);
  std::atomic_thread_fence(std::memory_order_seq_cst);
  cpuset_destroy(cset);
#endif
  if (err != 0) {
    LOG(ERROR) << "setaffinity failed: " << strerror(err);
  }
  return err == 0;
}

std::vector<std::string> ReadDict() {
  // Dictionary search paths
  const static char *dicts[] = {
      "/usr/share/dict/words",
      "words",
  };
  std::vector<std::string> words;
  std::ifstream f;

  for (const auto &d : dicts) {
    f.open(d, std::ifstream::in);
    if (f.is_open()) break;
    f.clear();
  }

  if (!f.is_open()) return words;

  LOG(DEBUG) << "Reading words.";

  std::string word;
  while (!f.eof()) {
    std::getline(f, word);
    words.push_back(word);
  }
  f.close();
  LOG(DEBUG) << "Read " << words.size() << " words.";
  std::sort(words.begin(), words.end(),
            [](const std::string &a, const std::string &b) {
              return a.size() < b.size();
            });
  return words;
}

class Worker {
 public:
  Worker(const std::vector<std::string> *words, int tid)
      : tid_(tid), words_(words), rndeng_(std::random_device()()) {}
  ~Worker() {}
  void Run();

 private:
  void FillBufferRandomData(std::string *s);
  void FillBufferRandomText(std::string *s);
  void MaybeMadviseDontNeed(std::string *s);

  const int tid_;
  const std::vector<std::string> *words_;
  // We don't really need "good" random numbers.
  // std::mt19937_64 rndeng_;
  std::knuth_b rndeng_;
};

void Worker::FillBufferRandomData(std::string *s) {
  std::uniform_int_distribution<int> dist(0, 255);
  for (uint32_t i = 0; i < s->size(); i++) {
    (*s)[i] = dist(rndeng_);
  }
}

void Worker::FillBufferRandomText(std::string *s) {
  std::exponential_distribution<double> dist(20);
  int pos = 0;
  int bufsize = s->size();
  while (pos < bufsize) {
    uint32_t r = static_cast<uint32_t>(dist(rndeng_) * words_->size());
    if (r >= words_->size()) {
      r = words_->size() - 1;
    }
    const auto &word = (*words_)[r];
    int wordlen = word.size();
    if (pos + wordlen >= bufsize) {
      break;
    }
    s->replace(pos, wordlen, word);
    pos += wordlen;
    if (pos < bufsize) {
      (*s)[pos++] = ' ';
    }
  }
  // Pad with spaces
  while (pos < bufsize) {
    (*s)[pos++] = ' ';
  }
}

void Worker::MaybeMadviseDontNeed(std::string *s) {
  static long pagesize = sysconf(_SC_PAGESIZE);
  // Half the time, tell the OS to release the destination buffer.
  if (std::uniform_int_distribution<int>(0, 1)(rndeng_)) {
    // Round up the buffer start address to a page boundary.
    intptr_t start = ((intptr_t) & (*s)[0] + pagesize - 1) & ~(pagesize - 1);
    // Round down the buffer end address to a page boundary.
    intptr_t end = ((intptr_t) & (*s)[s->size() - 1]) & ~(pagesize - 1);
    if (end - start >= pagesize) {
      if (madvise((char *)start, end - start, MADV_DONTNEED) == -1) {
        LOG(WARN) << "tid " << tid_
                  << " madvise(MADV_DONTNEED) failed: " << strerror(errno);
      }
    }
  }
}

std::string OpenSSL_Hash(const std::string &s, const EVP_MD *type) {
  EVP_MD_CTX *ctx;
  ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, type, nullptr);
  std::string hash;
  hash.resize(EVP_MD_CTX_size(ctx));
  EVP_DigestUpdate(ctx, s.data(), s.size());
  EVP_DigestFinal_ex(ctx, (uint8_t *)&hash[0], nullptr);
  EVP_MD_CTX_destroy(ctx);
  return HexStr(hash);
}

void Worker::Run() {
  LOG(INFO) << "tid " << tid_ << " starting";

  // Array of random data generators.
  typedef struct {
    const char *name;
    void (Worker::*func)(std::string *);
  } generatorItem;
  std::vector<generatorItem> generators = {
      {"DATA", &Worker::FillBufferRandomData},
      {"TEXT", &Worker::FillBufferRandomText},
  };

  // Array of hash/checksum routines.
  typedef struct {
    const char *name;
    std::string (*func)(const std::string &);
  } hashItem;
  std::vector<hashItem> hashers = {
      {
          "MD5",
          [](const std::string &s) -> std::string {
            return OpenSSL_Hash(s, EVP_md5());
          },
      },
      {
          "SHA1",
          [](const std::string &s) -> std::string {
            return OpenSSL_Hash(s, EVP_sha1());
          },
      },
      {
          "SHA256",
          [](const std::string &s) -> std::string {
            return OpenSSL_Hash(s, EVP_sha256());
          },
      },
      {
          "SHA512",
          [](const std::string &s) -> std::string {
            return OpenSSL_Hash(s, EVP_sha512());
          },
      },
      {
          "ALDER32",  // exported by zlib
          [](const std::string &s) -> std::string {
            uLong c = adler32(0, Z_NULL, 0);
            c = adler32(c, (const Bytef *)s.data(), s.size());
            return HexData((const char *)&c, sizeof(c));
          },
      },
      {
          "CRC32",  // exported by zlib.
          [](const std::string &s) -> std::string {
            uLong c = crc32(0, Z_NULL, 0);
            c = crc32(c, (const Bytef *)s.data(), s.size());
            return HexData((const char *)&c, sizeof(c));
          },
      },
      {
          "CRC32C",  // crc32 instruction on SSSE3
          [](const std::string &s) -> std::string {
            uint32_t c = crc32c(s.data(), s.size());
            return HexData((const char *)&c, sizeof(c));
          },
      },
      {
          "FarmHash64",  // Google farmhash
          [](const std::string &s) -> std::string {
            uint64_t c = util::Hash64(s.data(), s.size());
            return HexData((const char *)&c, sizeof(c));
          },
      },
  };

  // Array of compression routines.
  typedef struct {
    const char *name;
    int (*enc)(std::string *, const std::string &);
    int (*dec)(std::string *, const std::string &);
  } compressorItem;
  std::vector<compressorItem> compressors = {
      {
          "ZLIB",
          [](std::string *o, const std::string &s) {
            uLongf olen = compressBound(s.size());
            o->resize(olen);
            int err = compress2((Bytef *)&(*o)[0], &olen, (Bytef *)s.data(),
                                s.size(), Z_BEST_SPEED);
            if (err != Z_OK) {
              LOG(DEBUG) << "zlib compression failed: " << err
                         << " srclen: " << s.size()
                         << " destlen: " << o->size();
              return err;
            }
            o->resize(olen);
            return 0;
          },
          [](std::string *o, const std::string &s) {
            uLongf olen = o->size();
            int err = uncompress((Bytef *)&(*o)[0], &olen, (Bytef *)s.data(),
                                 s.size());
            if (err != Z_OK) {
              LOG(DEBUG) << "zlib decompression failed: " << err
                         << " srclen: " << s.size()
                         << " destlen: " << o->size();
              return err;
            }
            o->resize(olen);
            return 0;
          },
      },
  };

  // Use a normal distribution for random buffer size.
  std::normal_distribution<double> buf_size_dist((BUF_MAX - BUF_MIN) / 2,
                                                 (BUF_MAX - BUF_MIN) / 3);
  auto BufSize = std::bind(buf_size_dist, rndeng_);

  // Choose generator and compressor uniformly.
  std::uniform_int_distribution<int> gen_dist(0, generators.size() - 1);
  auto Gen = std::bind(gen_dist, rndeng_);
  std::uniform_int_distribution<int> comp_dist(0, compressors.size() - 1);
  auto Comp = std::bind(comp_dist, rndeng_);

  // Run every hash routine, every time.
  std::string hashes[hashers.size()];

  EVP_CIPHER_CTX *cipher_ctx;
  cipher_ctx = EVP_CIPHER_CTX_new();
  std::string src_buf, dst_buf;

  while (!exiting) {
    if (std::thread::hardware_concurrency() > 1) {
      SetAffinity(tid_);
    }
    int err;
    int32_t bufsize = BufSize();
    if (bufsize < 8) bufsize = 8;
    if (bufsize > BUF_MAX) bufsize = BUF_MAX;
    src_buf.resize(bufsize);
    auto &gen = generators[Gen()];
    auto &comp = compressors[Comp()];
    std::stringstream block_summary;
    block_summary << gen.name << " size " << bufsize << " " << comp.name;
    std::stringstream writer_info;
    writer_info << "CPU tids (writer " << tid_ << ") " << block_summary.str()
                << " ";

    (this->*gen.func)(&src_buf);
    LOG(DEBUG) << writer_info.str() << "gen done.";

    // Run all the hash funcs.

    for (uint32_t i = 0; i < hashers.size(); i++) {
      if (exiting) break;
      hashes[i] = hashers[i].func(src_buf);
    }
    LOG(DEBUG) << writer_info.str() << "initial hashes done.";
    if (exiting) break;

    // Run our randomly chosen compressor.

    err = comp.enc(&dst_buf, src_buf);
    LOG(DEBUG) << writer_info.str() << "src_buf.size(): " << src_buf.size()
               << ", dst_buf.size(): " << dst_buf.size() << ".";
    std::swap(src_buf, dst_buf);
    dst_buf.clear();
    if (err) {
      LOG(ERROR) << writer_info.str() << "compression failed: " << err;
      errorCount++;
      continue;
    }
    LOG(DEBUG) << writer_info.str() << "compress done.";
    if (exiting) break;

    // Encrypt.

    const unsigned char key[33] = "0123456789abcdef0123456789abcdef";
    std::string ivec(12, 0);
    unsigned char gmac[16];
    FillBufferRandomData(&ivec);

    int enc_len = 0, enc_unused_len = 0;
    EVP_CipherInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, key,
                      (unsigned char *)ivec.data(), 1);

    dst_buf.resize(src_buf.size());
    MaybeMadviseDontNeed(&dst_buf);
    if (EVP_CipherUpdate(cipher_ctx, (unsigned char *)&dst_buf[0], &enc_len,
                         (unsigned char *)src_buf.data(),
                         src_buf.size()) != 1) {
      LOG(ERROR) << writer_info.str() << "EVP_CipherUpdate failed";
      errorCount++;
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      dst_buf.erase();
      continue;
    }
    if (EVP_CipherFinal_ex(cipher_ctx, nullptr, &enc_unused_len) != 1) {
      LOG(ERROR) << writer_info.str() << "encrypt EVP_CipherFinal_ex failed";
      errorCount++;
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      dst_buf.erase();
      continue;
    }
    enc_len += enc_unused_len;
    if (enc_len != (int)dst_buf.size()) {
      LOG(ERROR) << writer_info.str() << "encrypt length mismatch: " << enc_len
                 << " vs " << dst_buf.size();
      errorCount++;
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      dst_buf.erase();
      continue;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, sizeof(gmac),
                            gmac) != 1) {
      LOG(ERROR) << writer_info.str() << "EVP_CTRL_GCM_GET_TAG failed";
      errorCount++;
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      dst_buf.erase();
      continue;
    }
    EVP_CIPHER_CTX_cleanup(cipher_ctx);
    std::swap(src_buf, dst_buf);
    dst_buf.clear();
    LOG(DEBUG) << writer_info.str() << "encrypt done.";
    if (exiting) break;

    // Make a copy.
    // Do the copy in two steps, stress alignment handling.
    dst_buf.resize(src_buf.size());
    MaybeMadviseDontNeed(&dst_buf);
    int offset =
        std::uniform_int_distribution<int>(1, src_buf.size() - 1)(rndeng_);
#if defined(__i386__) || defined(__x86_64__)
    __movsb(&dst_buf[0], &src_buf[0], offset);
    __movsb(&dst_buf[offset], &src_buf[offset], src_buf.size() - offset);
#else
    memcpy(&dst_buf[0], &src_buf[0], offset);
    memcpy(&dst_buf[offset], &src_buf[offset], src_buf.size() - offset);
#endif
    std::swap(src_buf, dst_buf);
    dst_buf.clear();

    // Switch to an alternate CPU.

    int newcpu = tid_;
    if (std::thread::hardware_concurrency() > 1) {
      std::vector<int> cpus;
      for (int i = 0; i < static_cast<int>(std::thread::hardware_concurrency());
           i++) {
        if (i == tid_) continue;
        cpus.push_back(i);
      }
      int cpuoff =
          std::uniform_int_distribution<int>(0, cpus.size() - 1)(rndeng_);
      newcpu = cpus[cpuoff];
      cpus.erase(cpus.begin() + cpuoff);
      SetAffinity(newcpu);
    }

    std::stringstream writer_reader;
    writer_reader << "CPU tids (writer " << tid_ << " reader " << newcpu << ") "
                  << block_summary.str() << " ";

    // Decrypt.

    int dec_len = 0, dec_extra_len = 0;
    EVP_CipherInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, key,
                      (unsigned char *)ivec.data(), 0);
    dst_buf.resize(src_buf.size());
    MaybeMadviseDontNeed(&dst_buf);
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gmac),
                            gmac) != 1) {
      LOG(ERROR) << writer_reader.str() << "EVP_CTRL_GCM_SET_TAG failed";
      errorCount++;
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      dst_buf.erase();
      continue;
    }
    if (EVP_CipherUpdate(cipher_ctx, (unsigned char *)&dst_buf[0], &dec_len,
                         (unsigned char *)src_buf.data(),
                         src_buf.size()) != 1) {
      LOG(ERROR) << writer_reader.str() << "decryption failed";
      errorCount++;
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      dst_buf.erase();
      continue;
    }
    if (EVP_CipherFinal_ex(cipher_ctx, (unsigned char *)&dst_buf[dec_len],
                           &dec_extra_len) != 1) {
      LOG(ERROR) << writer_reader.str() << "decrypt EVP_CipherFinal_ex failed";
      errorCount++;
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      dst_buf.erase();
      continue;
    }
    dec_len += dec_extra_len;
    EVP_CIPHER_CTX_cleanup(cipher_ctx);
    if (dec_len != (int)dst_buf.size()) {
      LOG(ERROR) << writer_reader.str()
                 << "decrypt length mismatch: " << dec_len << " vs "
                 << dst_buf.size();
      errorCount++;
      dst_buf.erase();
      continue;
    }
    std::swap(src_buf, dst_buf);
    dst_buf.clear();
    LOG(DEBUG) << writer_reader.str() << "decrypt done.";
    if (exiting) break;

    // Run decompressor.

    dst_buf.resize(bufsize);
    MaybeMadviseDontNeed(&dst_buf);
    err = comp.dec(&dst_buf, src_buf);
    std::swap(src_buf, dst_buf);
    dst_buf.clear();
    if (err) {
      LOG(ERROR) << writer_reader.str() << "uncompression failed: " << err;
      errorCount++;
      continue;
    }
    if (src_buf.size() != bufsize) {
      LOG(ERROR) << writer_reader.str()
                 << "uncompressed buffer size mismatch: should be " << bufsize
                 << " got " << src_buf.size();
      errorCount++;
      continue;
    }
    LOG(DEBUG) << writer_reader.str() << "uncompress done.";

    // Re-run hash funcs.

    bool error = false;
    for (uint32_t i = 0; i < hashers.size(); i++) {
      if (exiting) break;
      std::string hash = hashers[i].func(src_buf);
      if (hashes[i] != hash) {
        LOG(ERROR) << writer_reader.str() << hashers[i].name
                   << " hash mismatch (" << hash << " vs " << hashes[i];
        error = true;
        errorCount++;
      }
    }
    LOG(DEBUG) << writer_reader.str() << "rehash done.";

    // Cleanup
    src_buf.clear();
    if (!error) {
      successCount++;
    }
  }
  EVP_CIPHER_CTX_free(cipher_ctx);
  LOG(INFO) << "tid " << tid_ << " exiting.";
}

int main(int argc, char **argv) {
  LOG(INFO) << "Starting " << argv[0] << " version " cpu_check_VERSION;
  std::vector<std::thread *> tids;
  std::vector<Worker *> workers;
  std::vector<std::string> words = ReadDict();
  if (words.size() == 0) {
    LOG(ERROR) << "No word list found.";
    exit(1);
  }
  int cpus = std::thread::hardware_concurrency();
  LOG(INFO) << "Detected hardware concurrency: " << cpus;
  for (int i = 0; i < cpus; i++) {
    workers.push_back(new Worker(&words, i));
    tids.push_back(new std::thread(&Worker::Run, workers[i]));
  }
  signal(SIGTERM, [](int) { exiting = true; });
  signal(SIGINT, [](int) { exiting = true; });

  struct timeval last_time;
  gettimeofday(&last_time, nullptr);
  struct timeval last_cpu = {0, 0};
  while (!exiting) {
    sleep(5);
    struct rusage ru;
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    float secs = (((tv.tv_sec - last_time.tv_sec) * 1000000.0) +
                  (tv.tv_usec - last_time.tv_usec)) /
                 1000000.0;
    if (getrusage(RUSAGE_SELF, &ru) == -1) {
      LOG(ERROR) << "getrusage failed: " << strerror(errno);
    } else {
      float cpu = (((ru.ru_utime.tv_sec - last_cpu.tv_sec) * 1000000.0) +
                   (ru.ru_utime.tv_usec - last_cpu.tv_usec)) /
                  1000000.0;
      LOG(INFO) << "Running. CPU " << cpu / secs << " s/s";
      last_cpu = ru.ru_utime;
    }
    last_time = tv;
  }

  // shutting down.
  for (int i = 0; i < cpus; i++) {
    auto &t = tids.back();
    t->join();
    delete t;
    tids.pop_back();
  }
  for (auto w : workers) {
    delete w;
  }
  LOG(ERROR) << errorCount.load() << " ERRORS, " << successCount.load()
             << " SUCCESSES.";
  LOG(INFO) << "Exiting.";
  exit(errorCount != 0);
}
