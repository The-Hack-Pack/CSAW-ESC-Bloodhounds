/* Dual-mode harness:
 *   - libFuzzer / AFL++ (LLVMFuzzerTestOneInput) when built with clang
 *   - plain stdin reader otherwise, so AFL++ in qemu/afl-gcc mode works
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "target.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;
    switch (data[0] & 0x01) {
    case 0:
        parse_config(data + 1, size - 1);
        break;
    case 1:
        if (size >= 3) {
            eeprom_write(0, data + 1, size - 1 > 128 ? 128 : size - 1);
            check_credential(data[1] % 120);
        }
        break;
    }
    return 0;
}

#ifndef FUZZING_ENGINE
int main(void)
{
    static uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    return LLVMFuzzerTestOneInput(buf, n);
}
#endif
