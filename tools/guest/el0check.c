// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026, NOFire AI
//
// Checks, from EL0, that trapped CNTFRQ_EL0/CNTVCT_EL0 reads return the
// hvi-time synthetic 54 MHz counter (now_ns * 54 / 1000), not the raw host
// counter, and prints the driver's sysfs self-check, among it
// "snapshot1: ... migrations=N". It is the acceptance test of the portable
// kernel's EL0 counter patch. Run as /init it mounts /sys and /proc and
// powers the guest off; with --no-poweroff it returns instead, which is how
// tools/mk-initramfs.py runs it from the checkpoint workload. It never
// sleeps.
// Build (static, aarch64): gcc -O2 -static -o el0check el0check.c
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uint64_t cntvct(void)
{
	uint64_t v;

	asm volatile("isb; mrs %0, cntvct_el0" : "=r"(v) :: "memory");
	return v;
}

static uint64_t cntfrq(void)
{
	uint64_t v;

	asm volatile("mrs %0, cntfrq_el0" : "=r"(v));
	return v;
}

static int read_file(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	return 0;
}

static uint64_t field(const char *snap, const char *key)
{
	char k[64];
	const char *p;

	snprintf(k, sizeof(k), " %s=", key);
	p = strstr(snap, k);
	return p ? strtoull(p + strlen(k), NULL, 10) : 0;
}

static void show(const char *path)
{
	char buf[512];

	if (read_file(path, buf, sizeof(buf)))
		printf("EL0CHECK %s: unreadable\n", path);
	else
		printf("EL0CHECK %s: %s", path, buf);
}

int main(int argc, char **argv)
{
	/* --no-poweroff returns after the checks, so the caller goes on. */
	int poweroff = !(argc > 1 && strcmp(argv[1], "--no-poweroff") == 0);
	char s1[512], s2[512];
	uint64_t frq, vct, ns1, ns2, lo, hi, raw1, raw2;
	struct timespec mono, real;
	int ok;

	mkdir("/sys", 0755);
	mkdir("/proc", 0755);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("proc", "/proc", "proc", 0, NULL);
	setvbuf(stdout, NULL, _IONBF, 0);

	show("/sys/devices/system/clocksource/clocksource0/current_clocksource");
	show("/sys/devices/system/clockevents/clockevent0/current_device");
	show("/sys/kernel/hvi_time/generation");
	show("/sys/kernel/hvi_time/counter_freq_hz");

	if (read_file("/sys/kernel/hvi_time/snapshot", s1, sizeof(s1))) {
		printf("EL0CHECK FAIL: no /sys/kernel/hvi_time/snapshot\n");
		goto out;
	}
	frq = cntfrq();
	vct = cntvct();
	read_file("/sys/kernel/hvi_time/snapshot", s2, sizeof(s2));
	printf("EL0CHECK snapshot1: %s", s1);
	printf("EL0CHECK snapshot2: %s", s2);

	ns1 = field(s1, "now_ns");
	ns2 = field(s2, "now_ns");
	raw1 = field(s1, "cntvct");
	raw2 = field(s2, "cntvct");
	lo = ns1 * 54 / 1000;
	hi = ns2 * 54 / 1000;
	ok = frq == 54000000 && vct >= lo && vct <= hi;
	printf("EL0CHECK el0 cntfrq=%" PRIu64 " cntvct=%" PRIu64
	       " expected [%" PRIu64 ", %" PRIu64 "] (now_ns*54/1000); raw counter was [%" PRIu64 ", %" PRIu64 "]\n",
	       frq, vct, lo, hi, raw1, raw2);
	printf("EL0CHECK %s\n", ok ? "PASS: EL0 sees the synthetic 54 MHz counter" :
	       "FAIL: EL0 counter is not the synthetic one");

	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);
	printf("EL0CHECK CLOCK_MONOTONIC %lld.%09ld CLOCK_REALTIME %lld.%09ld\n",
	       (long long)mono.tv_sec, mono.tv_nsec,
	       (long long)real.tv_sec, real.tv_nsec);
out:
	printf("EL0CHECK done\n");
	if (!poweroff)
		return 0;
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}
