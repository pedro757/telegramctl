#ifndef TELEGRAM_NATIVE_PROTOCOL_H
#define TELEGRAM_NATIVE_PROTOCOL_H

#define OK 0
#define FAILED 1
#define MISSING 10
#define EXISTS 11
#define MAX_PAYLOAD 16384

static int valid_target(const char *text) {
    static const char prefix[] = "telegram/profiles/";
    for (int i = 0; prefix[i]; i++) if (*text++ != prefix[i]) return 0;
    for (int i = 0; i < 97; i++) {
        char c = *text++;
        if (i == 64) {
            if (c != '/') return 0;
        } else if (!((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'))) {
            return 0;
        }
    }
    return *text == '\0';
}

#endif
