// SPDX-License-Identifier: GPL-2.0-or-later
//
// tlf_target: a benign standalone target for the Traceless-Frida end-to-end test.
// It exports secret() (page-aligned, in .dynsym so Frida resolves it by name) and
// loops printing secret(i). Each iteration it ALSO reads back the first instruction
// word of secret() from its own .text and prints it -- with a real inline hook that
// word changes (a branch is written over the prologue); with the traceless KPM hook
// it stays constant (the .text is never touched), which is the whole point.
//
// Build: test/build_target.ps1  ->  arm64, -rdynamic so `secret` is a dynamic export.

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* page-aligned + noinline: secret() owns its page, so the whole-page clone is clean
 * and easy to reason about. visibility default + -rdynamic put it in .dynsym. */
__attribute__((aligned(0x1000), noinline, visibility("default")))
int secret(int n)
{
    volatile int a = n * 3;
    volatile int b = a + 7;
    return b; /* secret(n) == n*3 + 7 */
}

/* a neighbour that shares secret()'s page-ROUNDED region only if small; kept on its
 * own to stay independent. Prints so you can confirm unrelated code is unaffected. */
__attribute__((noinline, visibility("default")))
int neighbour(int n) { return -n; }

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tlf_target pid=%d secret=%p neighbour=%p first_insn=0x%08x\n",
           getpid(), (void *)&secret, (void *)&neighbour, *(volatile uint32_t *)(uintptr_t)&secret);
    fflush(stdout);

    for (int i = 0;; i++) {
        int r = secret(i);
        uint32_t w0 = *(volatile uint32_t *)(uintptr_t)&secret; /* .text integrity witness */
        printf("[%4d] secret(%d)=%d  nb=%d  secret[0]=0x%08x\n", i, i, r, neighbour(i), w0);
        fflush(stdout);
        usleep(500000);
    }
    return 0;
}
