#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "dns_constants.h"

#define log_n_print(...) {                          \
  FILE *logfile = fopen(LOGFILE_FILENAME, "a");     \
  char __tmp__[4096];                               \
  memset(__tmp__, 0, 4096);                         \
  sprintf(__tmp__, __VA_ARGS__);                    \
  printf("%s", __tmp__);                            \
  fprintf(logfile, "%s", __tmp__);                  \
  fclose(logfile);                                  \
}                                                   \

void logging(char* msg, const char* type) {
    if (strcmp(type, "address") == 0) {
        log_n_print("[i] Getting address of website \"");
        while (*msg) {
            char count = *msg;
            while (count--) {
                msg++;
                log_n_print("%c", *msg);
            }
            msg++;
            log_n_print(".");
        }
        log_n_print("\b\"...\n");
    }

    if (strcmp(type, "") == 0) {
        log_n_print("%s\n", msg);
    }

    if (strcmp(type, "packet-hex") == 0) {
        log_n_print("[i] Printing packet in hexcode...\n");
        log_n_print("Position:    00 01 02 03 04 05 06 07 | 08 09 0a 0b 0c 0d 0e 0f\n");
        log_n_print("=================================================================\n");
        for (int i = 0; i < 32; ++i) {
            log_n_print("%10x:  %02x %02x %02x %02x %02x %02x %02x %02x   %02x %02x %02x %02x %02x %02x %02x %02x || ",
                i * 16,
                msg[i * 16 + 0] & 0xff,
                msg[i * 16 + 1] & 0xff,
                msg[i * 16 + 2] & 0xff,
                msg[i * 16 + 3] & 0xff,
                msg[i * 16 + 4] & 0xff,
                msg[i * 16 + 5] & 0xff,
                msg[i * 16 + 6] & 0xff,
                msg[i * 16 + 7] & 0xff,
                msg[i * 16 + 8] & 0xff,
                msg[i * 16 + 9] & 0xff,
                msg[i * 16 + 10] & 0xff,
                msg[i * 16 + 11] & 0xff,
                msg[i * 16 + 12] & 0xff,
                msg[i * 16 + 13] & 0xff,
                msg[i * 16 + 14] & 0xff,
                msg[i * 16 + 15] & 0xff
            );

            for (int j = 0; j < 16; ++j) {
                if (isprint(msg[i * 16 + j])) {log_n_print("%c", msg[i * 16 + j]);}
                else                          {log_n_print(".");                  }
            }
            log_n_print("\n");
        }
    }

    if (strcmp(type, "bit") == 0) {
        printf("[i] Bits: ");
        for (int i = 7; i >= 0; --i)
            printf((*msg >> i) & 0x1 ? "1" : "0");
        printf("\n");
    }

    if (strcmp(type, "hex") == 0) {
        printf("[i] Hex: ");
        for (int i = 4; i >= 0; i -= 4)
            printf("%01x", (*msg >> i) & 0xf);
        printf("\n");
    }
}
