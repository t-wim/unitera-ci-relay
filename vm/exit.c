/* Executed only in the synthetic guest, never on the host. */
#ifndef EXIT_VALUE
#error EXIT_VALUE_required
#endif
__attribute__((noreturn)) void _start(void) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(172L), "D"(3L)
                     : "rcx", "r11", "memory");
    if (result == 0) {
        __asm__ volatile("outl %0, %1" : : "a"((unsigned int)EXIT_VALUE), "Nd"((unsigned short)0xf4));
    }
    __asm__ volatile("syscall" : : "a"(60L), "D"(99L) : "rcx", "r11", "memory");
    for (;;) {}
}
