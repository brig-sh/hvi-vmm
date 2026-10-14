// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026, NOFire AI
//
// Writes argv[1] MiB of memory over and over, every 4 KiB page each pass,
// and checks that each page still holds what the pass before wrote: a page
// a live move failed to copy again after the guest wrote it shows up as
// DIRTY-BAD after the restore. With argv[2] "rand" (the default) each
// page is filled with pseudo-random words, which do not compress; with
// "word" only its first and last words change, which compress to almost
// nothing. Prints DIRTY-READY once its memory is in place, and a DIRTY
// line about once a second with the pass, the bad pages so far and the
// rate it writes at. tools/stream-e2e.sh --dirty-mib starts it.
// Build (static, aarch64): gcc -O2 -static -o dirty dirty.c
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

/* splitmix64: one step of a fast, well-mixed sequence. */
static uint64_t mix(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ULL;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

static double mono(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	size_t mib = argc > 1 ? strtoul(argv[1], NULL, 10) : 256;
	int rand = !(argc > 2 && strcmp(argv[2], "word") == 0);
	size_t pages = mib * 256;
	uint64_t *mem = mmap(NULL, pages * 4096, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	uint64_t pass = 0, bad = 0;
	double start, last;

	if (mem == MAP_FAILED) {
		perror("DIRTY-FAIL mmap");
		return 1;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("DIRTY-READY %zu MiB %s\n", mib, rand ? "rand" : "word");
	start = last = mono();
	for (;;) {
		pass++;
		for (size_t i = 0; i < pages; i++) {
			uint64_t *page = mem + i * 512;
			uint64_t tag = (pass << 32) | i;

			if (pass > 1) {
				uint64_t want = ((pass - 1) << 32) | i;

				if (page[0] != want || page[511] != ~want) {
					if (bad < 8)
						printf("DIRTY-BAD page %zu pass %" PRIu64
						       " holds %" PRIx64 " %" PRIx64 "\n",
						       i, pass, page[0], page[511]);
					bad++;
				}
			}
			page[0] = tag;
			if (rand) {
				uint64_t x = tag;

				for (int w = 1; w < 511; w++) {
					x = mix(x);
					page[w] = x;
				}
			}
			page[511] = ~tag;
		}
		double now = mono();

		if (now - last >= 1.0) {
			printf("DIRTY pass %" PRIu64 " bad %" PRIu64 " %.0f MiB/s\n",
			       pass, bad, (double)mib * pass / (now - start));
			last = now;
		}
	}
}
