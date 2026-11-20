// macOS Keychain adapter. Only the nonsecret record name is passed in argv.
#define _DARWIN_C_SOURCE
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "protocol.h"

static int is_pipe(int fd) {
    struct stat info;
    return !fstat(fd, &info) && (S_ISFIFO(info.st_mode) || S_ISSOCK(info.st_mode));
}

int main(int argc, char **argv) {
    if (argc != 3 || !valid_target(argv[2])) return FAILED;
    const char *op = argv[1];
    if (strcmp(op, "credential-put") && strcmp(op, "credential-get") &&
        strcmp(op, "credential-remove")) return FAILED;

    CFStringRef account = CFStringCreateWithCString(
        NULL, argv[2], kCFStringEncodingASCII);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef value = NULL;
    OSStatus status = errSecParam;
    unsigned char payload[MAX_PAYLOAD + 1];
    if (!account || !query) goto done;
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, CFSTR("org.telegram-cli.session"));
    CFDictionarySetValue(query, kSecAttrAccount, account);
    if (!strcmp(op, "credential-put")) {
        if (!is_pipe(STDIN_FILENO) || setvbuf(stdin, NULL, _IONBF, 0)) goto done;
        size_t size = fread(payload, 1, sizeof payload, stdin);
        if (ferror(stdin) || !size || size > MAX_PAYLOAD) goto done;
        // Avoid creating another user-space copy of the password here.
        value = CFDataCreateWithBytesNoCopy(NULL, payload, (CFIndex)size,
                                            kCFAllocatorNull);
        if (!value) goto done;
        CFDictionarySetValue(query, kSecValueData, value);
        status = SecItemAdd(query, NULL);
    } else if (!strcmp(op, "credential-get")) {
        if (!is_pipe(STDOUT_FILENO) || setvbuf(stdout, NULL, _IONBF, 0)) goto done;
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
        status = SecItemCopyMatching(query, &value);
        if (status == errSecSuccess) {
            if (!value || CFGetTypeID(value) != CFDataGetTypeID()) {
                status = errSecParam;
                goto done;
            }
            CFDataRef data = (CFDataRef)value;
            CFIndex size = CFDataGetLength(data);
            if (size < 1 || size > MAX_PAYLOAD ||
                fwrite(CFDataGetBytePtr(data), 1, (size_t)size, stdout) !=
                    (size_t)size || fflush(stdout) == EOF) status = errSecParam;
        }
    } else {
        status = SecItemDelete(query);
    }

done:
    if (query) CFRelease(query);
    if (value) CFRelease(value);
    if (account) CFRelease(account);
    for (volatile unsigned char *p = payload; p < payload + sizeof payload; p++)
        *p = 0;
    if (status == errSecSuccess) return OK;
    if (status == errSecItemNotFound) return MISSING;
    return FAILED;
}
