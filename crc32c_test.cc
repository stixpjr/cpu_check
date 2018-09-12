#include <string.h>

#include <iostream>
#include <random>

#include "crc32c.h"

extern "C" {
uint32_t crc32c_hw(const char *, size_t);
uint32_t crc32c_sw(const char *, size_t);
}

const int MINSIZE = 1;
const int MAXSIZE = 1048576;

int main(int argc, char **argv) {
	std::knuth_b rndeng((std::random_device()()));
	std::uniform_int_distribution<int> size_dist(MINSIZE, MAXSIZE);
	std::uniform_int_distribution<int> d_dist(0, 255);
	std::string buf;
	for (int i = 0; i < 100; i++) {
		size_t len = size_dist(rndeng);
		buf.resize(len);
		for (int j = 0; j < len; j++) {
			buf[j] = d_dist(rndeng);
		}
		uint32_t crc_hw = crc32c_hw(buf.data(), len);
		uint32_t crc_sw = crc32c_sw(buf.data(), len);
		if (crc_hw != crc_sw) {
			fprintf(stderr, "crc mismatch: hw 0x%08x vs sw 0x%08x buffer len %ld\n", crc_hw, crc_sw, len);
		}
		buf.clear();
	}
	return 0;
}
