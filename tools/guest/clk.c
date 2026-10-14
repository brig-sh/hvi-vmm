// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026, NOFire AI
//
// Prints the guest's clocks in nanoseconds every argv[1] milliseconds of
// CLOCK_MONOTONIC, as "CLK n realtime monotonic boottime", argv[2] times
// or forever. With a period of 0 it prints one line and exits.
// tools/migrate-e2e.sh starts it at boot, and reads each line against the
// host clock where hvi runs: the wall clock against the host's, and the
// monotonic clock for a step back or a gap over a move.
// Build (static, aarch64): gcc -O2 -static -o clk clk.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long long ns(clockid_t id)
{
	struct timespec ts;

	clock_gettime(id, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	long period_ms = argc > 1 ? atol(argv[1]) : 0;
	long count = argc > 2 ? atol(argv[2]) : 0;
	struct timespec next;

	clock_gettime(CLOCK_MONOTONIC, &next);
	for (long n = 1;; n++) {
		long long real = ns(CLOCK_REALTIME);
		long long mono = ns(CLOCK_MONOTONIC);
		long long boot = ns(CLOCK_BOOTTIME);

		printf("CLK %ld %lld %lld %lld\n", n, real, mono, boot);
		fflush(stdout);
		if (period_ms <= 0 || (count > 0 && n >= count))
			return 0;
		next.tv_nsec += (period_ms % 1000) * 1000000L;
		next.tv_sec += period_ms / 1000 + next.tv_nsec / 1000000000L;
		next.tv_nsec %= 1000000000L;
		while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL))
			;
	}
}
