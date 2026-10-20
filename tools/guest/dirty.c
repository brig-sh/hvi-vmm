// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026, NOFire AI
//
// Writes argv[1] MiB of memory and checks that each 4 KiB page still holds
// what was last written to it: a page a live move failed to copy again
// after the guest wrote it shows up as DIRTY-BAD after the restore. With
// argv[2] "rand" (the default) each page is filled with pseudo-random
// words, which do not compress; with "word" only its first and last words
// change, which compress to almost nothing.
//
// By default it rewrites every page each pass, over and over, as fast as
// it can. That never converges, but a page whose write a pre-copy round
// lost is written again in the next pass, so only a loss in the final
// round shows. With argv[3], a number of seconds, it writes each page
// once per cycle of that many seconds instead, in a pseudo-random order
// and at an even pace, and checks every page once a second. A page whose
// write any round lost then holds the cycle before's data while the
// record says it was written, until the next cycle reaches it.
//
// Prints DIRTY-READY once its memory is in place, and a DIRTY line about
// once a second with the pass (a check, with argv[3]), the bad pages so
// far and the rate it writes at. tools/stream-e2e.sh --dirty-mib starts
// it, and --dirty-once SECS passes argv[3].
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

/* Writes page `i` with the tag of pass or cycle `pass`. */
static void fill(uint64_t *page, uint64_t pass, size_t i, int rand)
{
	uint64_t tag = (pass << 32) | i;

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

/* Returns whether page `i` holds the tag of `pass`, and reports it if not. */
static int holds(const uint64_t *page, uint64_t pass, size_t i, uint64_t *bad)
{
	uint64_t want = (pass << 32) | i;

	if (page[0] == want && page[511] == ~want)
		return 1;
	if (*bad < 8)
		printf("DIRTY-BAD page %zu pass %" PRIu64 " holds %" PRIx64
		       " %" PRIx64 "\n", i, pass, page[0], page[511]);
	(*bad)++;
	return 0;
}

/* Rewrites every page each pass, as fast as it can. */
static void loop(uint64_t *mem, size_t pages, size_t mib, int rand)
{
	uint64_t pass = 0, bad = 0;
	double start, last;

	start = last = mono();
	for (;;) {
		pass++;
		for (size_t i = 0; i < pages; i++) {
			if (pass > 1)
				holds(mem + i * 512, pass - 1, i, &bad);
			fill(mem + i * 512, pass, i, rand);
		}
		double now = mono();

		if (now - last >= 1.0) {
			printf("DIRTY pass %" PRIu64 " bad %" PRIu64 " %.0f MiB/s\n",
			       pass, bad, (double)mib * pass / (now - start));
			last = now;
		}
	}
}

/*
 * Writes each page once per cycle of `secs` seconds, in an order shuffled
 * each cycle, and checks every page once a second against the cycle that
 * last wrote it.
 */
static void once(uint64_t *mem, size_t pages, int rand, double secs)
{
	uint32_t *order = malloc(pages * sizeof(*order));
	uint32_t *cycle_of = malloc(pages * sizeof(*cycle_of));
	uint64_t check = 0, bad = 0, written = 0;
	uint32_t cycle = 1;
	double start, cycle_start, last;
	struct timespec nap = { 0, 1000000 };

	if (!order || !cycle_of) {
		perror("DIRTY-FAIL malloc");
		exit(1);
	}
	for (size_t i = 0; i < pages; i++) {
		fill(mem + i * 512, 1, i, rand);
		cycle_of[i] = 1;
	}
	start = cycle_start = last = mono();
	for (;;) {
		cycle++;
		for (size_t i = 0; i < pages; i++)
			order[i] = i;
		for (size_t i = pages - 1; i > 0; i--) {
			size_t j = mix(((uint64_t)cycle << 32) | i) % (i + 1);
			uint32_t t = order[i];

			order[i] = order[j];
			order[j] = t;
		}
		size_t next = 0;

		while (next < pages) {
			double now = mono();
			size_t due = (size_t)((now - cycle_start) / secs * pages);

			if (due > pages)
				due = pages;
			for (; next < due; next++) {
				size_t i = order[next];

				fill(mem + i * 512, cycle, i, rand);
				cycle_of[i] = cycle;
				written++;
			}
			if (now - last >= 1.0) {
				check++;
				for (size_t i = 0; i < pages; i++)
					holds(mem + i * 512, cycle_of[i], i, &bad);
				printf("DIRTY pass %" PRIu64 " bad %" PRIu64
				       " %.0f MiB/s\n", check, bad,
				       written / 256.0 / (now - start));
				last = now;
			}
			nanosleep(&nap, NULL);
		}
		cycle_start += secs;
	}
}

int main(int argc, char **argv)
{
	size_t mib = argc > 1 ? strtoul(argv[1], NULL, 10) : 256;
	int rand = !(argc > 2 && strcmp(argv[2], "word") == 0);
	double secs = argc > 3 ? strtod(argv[3], NULL) : 0;
	size_t pages = mib * 256;
	uint64_t *mem = mmap(NULL, pages * 4096, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

	if (mem == MAP_FAILED) {
		perror("DIRTY-FAIL mmap");
		return 1;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (secs > 0) {
		printf("DIRTY-READY %zu MiB %s once every %.0f s\n", mib,
		       rand ? "rand" : "word", secs);
		once(mem, pages, rand, secs);
	}
	printf("DIRTY-READY %zu MiB %s\n", mib, rand ? "rand" : "word");
	loop(mem, pages, mib, rand);
	return 0;
}
