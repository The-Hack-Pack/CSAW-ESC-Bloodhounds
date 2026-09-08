#ifndef TARGET_H
#define TARGET_H
#include <stddef.h>
#include <stdint.h>

extern int g_widen_window;

void rfid_isr(const uint8_t *uid, size_t n);
int  handle_frame(void);
int  parse_config(const uint8_t *in, size_t len);
void eeprom_write(size_t off, const uint8_t *buf, size_t n);
int  check_credential(size_t off);
int  run_race(int iters, int widen);
int  run_cred_race(int iters, int widen);
int  run_cred_baseline(int checks);
#endif
