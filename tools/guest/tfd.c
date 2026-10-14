// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026, NOFire AI
//
// Arms a CLOCK_MONOTONIC timerfd for argv[1] seconds and waits for it, so a
// timer armed before a checkpoint can be seen to fire after the restore.
// Prints TIMERFD-ARMED and TIMERFD-FIRED with the guest's monotonic time.
// tools/checkpoint-e2e.sh --portable starts it just before the capture.
// Build (static, aarch64): gcc -O2 -static -o tfd tfd.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static double mono(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	double secs = argc > 1 ? atof(argv[1]) : 6;
	struct itimerspec its = { 0 };
	uint64_t n;
	double armed;
	int fd = timerfd_create(CLOCK_MONOTONIC, 0);

	if (fd < 0) {
		perror("timerfd_create");
		return 1;
	}
	its.it_value.tv_sec = (time_t)secs;
	its.it_value.tv_nsec = (long)((secs - (time_t)secs) * 1e9);
	armed = mono();
	if (timerfd_settime(fd, 0, &its, NULL) < 0) {
		perror("timerfd_settime");
		return 1;
	}
	printf("TIMERFD-ARMED %.6f %.3f\n", armed, secs);
	fflush(stdout);
	if (read(fd, &n, sizeof(n)) != sizeof(n)) {
		perror("read");
		return 1;
	}
	printf("TIMERFD-FIRED %.6f %.6f\n", mono(), mono() - armed);
	fflush(stdout);
	return 0;
}
