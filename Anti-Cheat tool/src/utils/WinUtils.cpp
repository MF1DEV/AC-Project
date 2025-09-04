#include "WinUtils.h"
#include "../core/Logger.h"

std::string WinUtils::getSystemInfo() {
    json systemInfo;

    // OS Version - Use RtlGetVersion instead of deprecated GetVersionEx
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr != nullptr) {
            RTL_OSVERSIONINFOW rovi = { 0 };
            rovi.dwOSVersionInfoSize = sizeof(rovi);
            if (fxPtr(&rovi) == 0) {
                systemInfo["osVersion"] = std::to_string(rovi.dwMajorVersion) + "." +
                    std::to_string(rovi.dwMinorVersion) + "." +
                    std::to_string(rovi.dwBuildNumber);
            }
        }
    }

    // Computer name
    systemInfo["computerName"] = getComputerName();

    // Username
    systemInfo["userName"] = getCurrentUserName();

    // Machine GUID
    systemInfo["machineGuid"] = getMachineGuid();

    // CPU info
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    systemInfo["processorCount"] = sysInfo.dwNumberOfProcessors;
    systemInfo["processorArchitecture"] = sysInfo.wProcessorArchitecture;

    // Memory info
    MEMORYSTATUSEX memStatus = {};
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    systemInfo["totalMemoryMB"] = memStatus.ullTotalPhys / (1024 * 1024);

    // VM detection
    systemInfo["isVirtualMachine"] = isVirtualMachine();

    return systemInfo.dump();
}

std::string WinUtils::getCurrentUserName() {
    char username[UNLEN + 1];
    DWORD usernameLen = UNLEN + 1;

    if (GetUserNameA(username, &usernameLen)) {
        return std::string(username);
    }

    return "Unknown";
}

std::string WinUtils::getComputerName() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);

    if (GetComputerNameA(computerName, &size)) {
        return std::string(computerName);
    }

    return "Unknown";
}

std::string WinUtils::getMachineGuid() {
    return readRegistryString(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",
        "MachineGuid");
}

bool WinUtils::isProcessElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }

        CloseHandle(hToken);
    }

    return isElevated == TRUE;
}

bool WinUtils::enableDebugPrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    // Use ANSI version and cast the constant properly
    LPCSTR debugPrivilege = "SeDebugPrivilege";
    if (!LookupPrivilegeValueA(nullptr, debugPrivilege, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) == TRUE;
    CloseHandle(hToken);

    return result;
}

std::vector<std::string> WinUtils::getRunningServices() {
    std::vector<std::string> services;

    SC_HANDLE scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) return services;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // Get required buffer size
    EnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
        nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    if (bytesNeeded > 0) {
        std::vector<BYTE> buffer(bytesNeeded);
        LPENUM_SERVICE_STATUS_PROCESSA serviceStatus =
            reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSA>(buffer.data());

        if (EnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
            buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned,
            &resumeHandle, nullptr)) {

            for (DWORD i = 0; i < servicesReturned; ++i) {
                services.push_back(std::string(serviceStatus[i].lpServiceName));
            }
        }
    }

    CloseServiceHandle(scManager);
    return services;
}

bool WinUtils::isVirtualMachine() {
    // Check for common VM artifacts

    // 1. Check registry for VM signatures
    std::vector<std::pair<std::string, std::string>> vmRegKeys = {
        {"HARDWARE\\Description\\System", "SystemBiosVersion"},
        {"HARDWARE\\Description\\System", "VideoBiosVersion"},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId"}
    };

    for (const auto& regKey : vmRegKeys) {
        std::string value = readRegistryString(HKEY_LOCAL_MACHINE, regKey.first, regKey.second);
        std::transform(value.begin(), value.end(), value.begin(), ::tolower);

        if (value.find("vmware") != std::string::npos ||
            value.find("virtualbox") != std::string::npos ||
            value.find("vbox") != std::string::npos ||
            value.find("qemu") != std::string::npos ||
            value.find("virtual") != std::string::npos) {
            return true;
        }
    }

    // 2. Check for VM processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            do {
                // Convert TCHAR to std::string
                std::string processName;
#ifdef UNICODE
                // Convert wide string to narrow string
                int size = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
                if (size > 0) {
                    std::vector<char> buffer(size);
                    WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, buffer.data(), size, nullptr, nullptr);
                    processName = std::string(buffer.data());
                }
#else
                processName = std::string(pe32.szExeFile);
#endif

                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

                if (processName.find("vmware") != std::string::npos ||
                    processName.find("vbox") != std::string::npos ||
                    processName.find("qemu") != std::string::npos) {
                    CloseHandle(snapshot);
                    return true;
                }
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }

    // 3. Check CPU features (simplified)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) { // Hypervisor present bit
        return true;
    }

    return false;
}

std::string WinUtils::readRegistryString(HKEY hKey, const std::string& subKey, const std::string& valueName) {
    HKEY hSubKey;
    if (RegOpenKeyExA(hKey, subKey.c_str(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS) {
        return "";
    }

    char data[1024];
    DWORD dataSize = sizeof(data);
    DWORD dataType;

    if (RegQueryValueExA(hSubKey, valueName.c_str(), nullptr, &dataType,
        reinterpret_cast<LPBYTE>(data), &dataSize) == ERROR_SUCCESS) {
        RegCloseKey(hSubKey);
        if (dataType == REG_SZ) {
            return std::string(data);
        }
    }

    RegCloseKey(hSubKey);
    return "";
}