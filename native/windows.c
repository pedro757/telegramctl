// Native Windows credential, local filesystem and controlling-console APIs.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <wincred.h>
#include <shlobj.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>
#undef FAILED // winerror.h uses this name for an unrelated HRESULT check.
#include "protocol.h"

#define WIS(op) (!wcscmp(argv[1], L##op))

static int pipe_input(unsigned char *bytes, DWORD capacity, DWORD *size) {
    HANDLE pipe = GetStdHandle(STD_INPUT_HANDLE);
    if (GetFileType(pipe) != FILE_TYPE_PIPE) return 0;
    *size = 0;
    while (*size < capacity) {
        DWORD read = 0;
        if (!ReadFile(pipe, bytes + *size, capacity - *size, &read, NULL))
            return GetLastError() == ERROR_BROKEN_PIPE;
        if (!read) return 1;
        *size += read;
    }
    return 0;
}

static int pipe_output(const void *bytes, DWORD size) {
    DWORD written = 0;
    HANDLE pipe = GetStdHandle(STD_OUTPUT_HANDLE);
    return GetFileType(pipe) == FILE_TYPE_PIPE &&
           (!size || (WriteFile(pipe, bytes, size, &written, NULL) &&
                      written == size));
}

static int known_downloads(void) {
    static const GUID downloads = {
        0x374de290, 0x123f, 0x4565, {0x91, 0x64, 0x39, 0xc4, 0x92, 0x5e, 0x46, 0x7b}
    };
    PWSTR path = NULL;
    HRESULT status = SHGetKnownFolderPath(&downloads, KF_FLAG_DONT_VERIFY,
                                          NULL, &path);
    unsigned char bytes[MAX_PAYLOAD];
    int length = status == S_OK && path ? WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, path, -1,
        (char *)bytes, sizeof bytes, NULL, NULL) : 0;
    CoTaskMemFree(path);
    return length > 1 && pipe_output(bytes, length - 1) ? OK : FAILED;
}

static int credential(int argc, wchar_t **argv) {
    char name[128];
    if (argc != 3 ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[2], -1,
                             name, sizeof name, NULL, NULL) ||
        !valid_target(name)) return FAILED;
    PCREDENTIALW saved = NULL;
    if (WIS("credential-get")) {
        if (!CredReadW(argv[2], CRED_TYPE_GENERIC, 0, &saved))
            return GetLastError() == ERROR_NOT_FOUND ? MISSING : FAILED;
        DWORD size = saved->CredentialBlobSize;
        int ok = size && size <= CRED_MAX_CREDENTIAL_BLOB_SIZE &&
                 pipe_output(saved->CredentialBlob, size);
        SecureZeroMemory(saved->CredentialBlob, size);
        CredFree(saved);
        return ok ? OK : FAILED;
    }
    if (WIS("credential-remove")) {
        if (CredDeleteW(argv[2], CRED_TYPE_GENERIC, 0)) return OK;
        return GetLastError() == ERROR_NOT_FOUND ? MISSING : FAILED;
    }
    if (!WIS("credential-put")) return FAILED;
    if (CredReadW(argv[2], CRED_TYPE_GENERIC, 0, &saved)) {
        SecureZeroMemory(saved->CredentialBlob, saved->CredentialBlobSize);
        CredFree(saved);
        return EXISTS;
    }
    if (GetLastError() != ERROR_NOT_FOUND) return FAILED;
    unsigned char bytes[CRED_MAX_CREDENTIAL_BLOB_SIZE + 1];
    DWORD size;
    int result = FAILED;
    if (pipe_input(bytes, sizeof bytes, &size) && size) {
        CREDENTIALW entry = {0};
        entry.Type = CRED_TYPE_GENERIC;
        entry.TargetName = argv[2];
        entry.CredentialBlobSize = size;
        entry.CredentialBlob = bytes;
        entry.Persist = CRED_PERSIST_LOCAL_MACHINE;
        if (CredWriteW(&entry, 0)) result = OK;
    }
    SecureZeroMemory(bytes, sizeof bytes);
    return result;
}

// Only these principals are trusted alongside the Windows user. A directory
// above the private tree may allow other users to list/traverse it, but may
// not let them replace an existing component or change its ACL/reparse data.
static struct {
    TOKEN_USER *token_user;
    PSID installer;
    PSECURITY_DESCRIPTOR directory_sd;
} security;

static void free_security(void) {
    LocalFree(security.directory_sd);
    LocalFree(security.token_user);
    LocalFree(security.installer);
}

static int init_security(int create, int directory) {
    HANDLE token;
    DWORD size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (size) security.token_user = LocalAlloc(LMEM_FIXED, size);
    int ok = security.token_user &&
             GetTokenInformation(token, TokenUser, security.token_user,
                                 size, &size);
    CloseHandle(token);
    if (!ok || !ConvertStringSidToSidW(
            L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            &security.installer)) return 0; // Windows TrustedInstaller
    if (!create) return 1;
    wchar_t *sid = NULL, sddl[512];
    if (!ConvertSidToStringSidW(security.token_user->User.Sid, &sid)) return 0;
    const wchar_t *inherit = directory ? L"OICI" : L"";
    int length = swprintf(sddl, sizeof sddl / sizeof *sddl,
                          L"O:%lsD:P(A;%ls;FA;;;%ls)(A;%ls;FA;;;SY)"
                          L"(A;%ls;FA;;;BA)", sid, inherit, sid, inherit,
                          inherit);
    LocalFree(sid);
    return length > 0 && ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, &security.directory_sd, NULL);
}

static int trusted(PSID sid) {
    return EqualSid(sid, security.token_user->User.Sid) ||
           IsWellKnownSid(sid, WinLocalSystemSid) ||
           IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
           EqualSid(sid, security.installer);
}

enum path_acl { NO_ACL, ANCESTOR, PRIVATE_LEAF, DOWNLOAD_DIR };

static int safe_acl(HANDLE handle, enum path_acl kind) {
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, NULL, &dacl, NULL, &sd);
    int ok = result == ERROR_SUCCESS && dacl && owner && IsValidAcl(dacl) &&
             (kind == ANCESTOR ? trusted(owner)
                               : EqualSid(owner, security.token_user->User.Sid));
    for (DWORD i = 0; ok && i < dacl->AceCount; i++) {
        ACE_HEADER *header = NULL;
        if (!GetAce(dacl, i, (void **)&header)) {
            ok = 0;
            break;
        }
        if (kind != PRIVATE_LEAF && (header->AceFlags & INHERIT_ONLY_ACE))
            continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        // Unknown allow/integrity/conditional rules fail closed.
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            ok = 0;
            break;
        }
        ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)header;
        PSID sid = &ace->SidStart;
        if (trusted(sid) ||
            ((header->AceFlags & INHERIT_ONLY_ACE) &&
             IsWellKnownSid(sid, WinCreatorOwnerSid))) continue;
        const DWORD dangerous = DELETE | WRITE_DAC | WRITE_OWNER |
            FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
            FILE_ADD_FILE | GENERIC_ALL | GENERIC_WRITE | MAXIMUM_ALLOWED;
        if (kind == PRIVATE_LEAF || (ace->Mask & dangerous) ||
            (kind == DOWNLOAD_DIR && (ace->Mask & FILE_ADD_SUBDIRECTORY)))
            ok = 0;
    }
    LocalFree(sd);
    return ok;
}

// For file paths, the parent chain is validated separately from the leaf so
// attachments need not themselves be private. Private leaf checks are also
// used for user-supplied legacy imports (including those outside CLI state).
static int inspect(const wchar_t *path, int directory, enum path_acl acl) {
    HANDLE handle = CreateFileW(path, FILE_READ_ATTRIBUTES |
                                     (acl ? READ_CONTROL : 0),
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD last = GetLastError();
        return last == ERROR_FILE_NOT_FOUND || last == ERROR_PATH_NOT_FOUND
            ? MISSING : FAILED;
    }
    BY_HANDLE_FILE_INFORMATION info;
    int ok = GetFileType(handle) == FILE_TYPE_DISK &&
             GetFileInformationByHandle(handle, &info) &&
             !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
             !!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory &&
             (directory || acl != PRIVATE_LEAF || info.nNumberOfLinks == 1) &&
             (!acl || safe_acl(handle, acl));
    CloseHandle(handle);
    return ok ? OK : FAILED;
}

static int filesystem(int argc, wchar_t **argv) {
    if (argc != 3) return FAILED;
    int download_dir = WIS("path-download-dir"),
        create = WIS("path-mkdir"),
        leaf_dir = create || download_dir || WIS("path-directory"),
        file = WIS("path-file"), attachment = WIS("path-attachment"),
        parents = WIS("path-parents"), download = WIS("path-create-download"),
        new_file = download || WIS("path-create-file");
    if (!leaf_dir && !file && !parents && !attachment && !new_file)
        return FAILED;
    const wchar_t *source = argv[2];
    size_t size = wcslen(source);
    if (size < 3 || size > 32760 ||
        !((source[0] >= L'A' && source[0] <= L'Z') ||
          (source[0] >= L'a' && source[0] <= L'z')) ||
        source[1] != L':' || source[2] != L'\\') return FAILED;
    wchar_t root[] = {source[0], L':', L'\\', 0};
    DWORD flags;
    UINT drive = GetDriveTypeW(root);
    if ((drive != DRIVE_FIXED && drive != DRIVE_REMOVABLE &&
         drive != DRIVE_RAMDISK) ||
        !GetVolumeInformationW(root, NULL, 0, NULL, NULL, &flags, NULL, 0) ||
        !(flags & FILE_PERSISTENT_ACLS)) return FAILED;
    if (!init_security(create || new_file, create)) {
        free_security();
        return FAILED;
    }
    wchar_t *path = LocalAlloc(LMEM_FIXED, (size + 5) * sizeof *path);
    int result = FAILED;
    if (!path) goto done;
    memcpy(path, L"\\\\?\\", 4 * sizeof *path);
    memcpy(path + 4, source, (size + 1) * sizeof *path);
    wchar_t *part = path + 7;
    wchar_t first = *part;
    *part = 0;
    result = (size == 3 && !parents) ||
             (new_file && !wcschr(source + 3, L'\\'))
        ? FAILED : inspect(path, 1, ANCESTOR);
    *part = first;
    if (result != OK || !first) goto done;
    SECURITY_ATTRIBUTES sa = {sizeof sa, security.directory_sd, FALSE};
    for (wchar_t *p = part;; p++) {
        if (*p && *p != L'\\') {
            if (*p < 32 || wcschr(L"/:*?\"<>|", *p)) {
                result = FAILED;
                break;
            }
            continue;
        }
        if (p == part || p[-1] == L' ' || p[-1] == L'.') {
            result = FAILED;
            break;
        }
        int last = !*p, directory = !last || leaf_dir || parents;
        *p = 0;
        if (last && new_file) {
            HANDLE handle = CreateFileW(path, GENERIC_WRITE, 0, &sa,
                CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                NULL);
            if (handle != INVALID_HANDLE_VALUE) {
                result = CloseHandle(handle) ? OK : FAILED;
            } else {
                DWORD last_error = GetLastError();
                result = last_error == ERROR_FILE_EXISTS ||
                         last_error == ERROR_ALREADY_EXISTS ? EXISTS : FAILED;
            }
            break;
        }
        enum path_acl acl = PRIVATE_LEAF;
        if (last && attachment) acl = NO_ACL;
        else if (last && download_dir) acl = DOWNLOAD_DIR;
        else if (parents || (!last && !(new_file && !wcschr(p + 1, L'\\'))))
            acl = ANCESTOR;
        else if (download) acl = DOWNLOAD_DIR;
        result = inspect(path, directory, acl);
        if (result == MISSING && create) {
            if (!CreateDirectoryW(path, &sa) &&
                GetLastError() != ERROR_ALREADY_EXISTS) {
                result = FAILED;
                break;
            }
            result = inspect(path, 1, PRIVATE_LEAF);
        }
        if (last || result != OK) break;
        *p = L'\\';
        part = p + 1;
    }
done:
    LocalFree(path);
    free_security();
    return result;
}

static HANDLE console_input;
static DWORD input_mode;

static BOOL WINAPI restore_console(DWORD event) {
    (void)event;
    FlushConsoleInputBuffer(console_input);
    SetConsoleMode(console_input, input_mode);
    return FALSE; // Let Windows terminate the interrupted prompt.
}

static int prompt(int argc, wchar_t **argv) {
    if (argc != 3 || (!WIS("prompt-hidden") && !WIS("prompt-visible")))
        return FAILED;
    wchar_t *end;
    DWORD parent = wcstoul(argv[2], &end, 10), pids[128];
    DWORD processes = GetConsoleProcessList(pids, sizeof pids / sizeof *pids);
    int attached = 0;
    if (!parent || *end || processes > sizeof pids / sizeof *pids)
        return FAILED;
    for (DWORD i = 0; i < processes; i++) if (pids[i] == parent) attached = 1;
    if (!attached) return FAILED;
    unsigned char bytes[MAX_PAYLOAD + 1];
    wchar_t text[MAX_PAYLOAD + 1];
    DWORD size, count, out_mode;
    if (!pipe_input(bytes, sizeof bytes, &size) || !size) return FAILED;
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        (const char *)bytes, size, text, MAX_PAYLOAD);
    if (!length) return FAILED;
    console_input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE output = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    int result = FAILED, hidden = WIS("prompt-hidden"), installed = 0;
    if (console_input == INVALID_HANDLE_VALUE || output == INVALID_HANDLE_VALUE ||
        !GetConsoleMode(console_input, &input_mode) ||
        !GetConsoleMode(output, &out_mode) ||
        !SetConsoleCtrlHandler(restore_console, TRUE)) goto done;
    installed = 1;
    DWORD mode = (input_mode | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) &
                 ~(ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_ECHO_INPUT);
    if (!hidden) mode |= ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(console_input, mode)) goto done;
    if (!WriteConsoleW(output, text, length, &count, NULL) ||
        count != (DWORD)length) goto done;
    if (!ReadConsoleW(console_input, text, MAX_PAYLOAD + 1, &count, NULL))
        goto done;
    if (hidden) {
        DWORD written;
        if (!WriteConsoleW(output, L"\r\n", 2, &written, NULL) || written != 2)
            goto done;
    }
    if (!count || text[count - 1] != L'\n') {
        FlushConsoleInputBuffer(console_input);
        goto done;
    }
    count--;
    if (count && text[count - 1] == L'\r') count--;
    for (DWORD i = 0; i < count; i++)
        if (!text[i] || text[i] == L'\r' || text[i] == L'\n' ||
            text[i] == 0x1a) goto done;
    if (count) {
        length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text,
            count, (char *)bytes, MAX_PAYLOAD, NULL, NULL);
        if (!length) goto done;
    } else length = 0;
    if (pipe_output(bytes, length)) result = OK;
done:
    if (installed) {
        if (!SetConsoleMode(console_input, input_mode)) result = FAILED;
        SetConsoleCtrlHandler(restore_console, FALSE);
    }
    if (console_input != INVALID_HANDLE_VALUE) CloseHandle(console_input);
    if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    SecureZeroMemory(text, sizeof text);
    SecureZeroMemory(bytes, sizeof bytes);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) return FAILED;
    if (argc == 2 && WIS("known-downloads")) return known_downloads();
    if (!wcsncmp(argv[1], L"credential-", 11)) return credential(argc, argv);
    if (!wcsncmp(argv[1], L"path-", 5)) return filesystem(argc, argv);
    if (!wcsncmp(argv[1], L"prompt-", 7)) return prompt(argc, argv);
    return FAILED;
}
