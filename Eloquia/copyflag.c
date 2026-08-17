// copyflag.c
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

static void die(const char *msg) {
    DWORD e = GetLastError();
    fprintf(stderr, "[!] %s (GetLastError=%lu)\n", msg, (unsigned long)e);
    ExitProcess(1);
}

int main(int argc, char **argv) {
    const char *src = "C:\\Users\\Administrator\\Desktop\\root.txt";
    const char *dst = "C:\\temp\\root.txt";

    HANDLE hIn = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) die("CreateFileA(src) failed");

    HANDLE hOut = CreateFileA(dst, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) die("CreateFileA(dst) failed");

    BYTE buf[1 << 15]; // 32KB
    DWORD nRead = 0, nWritten = 0;

    while (ReadFile(hIn, buf, sizeof(buf), &nRead, NULL)) {
        if (nRead == 0) break;
        if (!WriteFile(hOut, buf, nRead, &nWritten, NULL) || nWritten != nRead)
            die("WriteFile(dst) failed");
    }

    DWORD last = GetLastError();
    if (last != ERROR_HANDLE_EOF && last != ERROR_SUCCESS) {
        die("ReadFile(src) failed");
    }

    CloseHandle(hOut);
    CloseHandle(hIn);
    return 0;
}
