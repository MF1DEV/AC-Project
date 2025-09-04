#include "DllInjectionDetector.h"
#include "../core/Logger.h"

DllInjectionDetector::DllInjectionDetector() {
    LOG_INFO("DllInjectionDetector initialized");
}

DllInjectionDetector::~DllInjectionDetector() {
    LOG_INFO("DllInjectionDetector destroyed");
}

std::vector<DetectionResult> DllInjectionDetector::detectInjectedDlls() {
    std::lock_guard<std::mutex> lock(detectorMutex);
    std::vector<DetectionResult> detections;

    // Get all running processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to create process snapshot for DLL detection");
        return detections;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {
        do {
            auto currentModules = getCurrentModules(pe32.th32ProcessID);

            // Check for new modules since last scan
            if (previousModules.find(pe32.th32ProcessID) != previousModules.end()) {
                std::vector<HMODULE> newModules;
                auto& prevMods = previousModules[pe32.th32ProcessID];

                for (const auto& mod : currentModules) {
                    if (std::find(prevMods.begin(), prevMods.end(), mod) == prevMods.end()) {
                        newModules.push_back(mod);
                    }
                }

                if (!newModules.empty()) {
                    auto newDetections = analyzeNewModules(pe32.th32ProcessID, newModules);
                    detections.insert(detections.end(), newDetections.begin(), newDetections.end());
                }
            }

            // Update cached modules
            previousModules[pe32.th32ProcessID] = currentModules;

            // Check for hooks in this process
            auto hookDetections = detectHooks(pe32.th32ProcessID);
            detections.insert(detections.end(), hookDetections.begin(), hookDetections.end());

            // Check for manual mapping
            if (detectManualMapping(pe32.th32ProcessID)) {
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

                DetectionResult detection(
                    DetectionType::DLL_INJECTION,
                    Severity::HIGH,
                    processName,
                    pe32.th32ProcessID,
                    "Manual DLL mapping detected"
                );
                detections.push_back(detection);
            }

        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);

    // Check for global hooks
    auto globalHookDetections = detectSetWindowsHookEx();
    detections.insert(detections.end(), globalHookDetections.begin(), globalHookDetections.end());

    return detections;
}

std::vector<HMODULE> DllInjectionDetector::getCurrentModules(DWORD processId) {
    std::vector<HMODULE> modules;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return modules;

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            modules.push_back(hMods[i]);
        }
    }

    CloseHandle(hProcess);
    return modules;
}

std::vector<DetectionResult> DllInjectionDetector::analyzeNewModules(DWORD processId, const std::vector<HMODULE>& newModules) {
    std::vector<DetectionResult> detections;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return detections;

    char processName[MAX_PATH];
    GetModuleBaseNameA(hProcess, nullptr, processName, sizeof(processName));

    for (const auto& hModule : newModules) {
        char modulePath[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, hModule, modulePath, sizeof(modulePath))) {

            // Check if module is legitimate
            if (!isModuleLegitimate(hModule, processId)) {
                DetectionResult detection(
                    DetectionType::DLL_INJECTION,
                    Severity::HIGH,
                    processName,
                    processId,
                    "Suspicious DLL loaded: " + std::string(modulePath)
                );

                // Add module path as evidence
                std::string modulePathStr(modulePath);
                detection.evidence.assign(modulePathStr.begin(), modulePathStr.end());

                detections.push_back(detection);
                LOG_WARNING("Suspicious DLL detected: " + std::string(modulePath) + " in process " + processName);
            }
        }
    }

    CloseHandle(hProcess);
    return detections;
}

bool DllInjectionDetector::isModuleLegitimate(HMODULE hModule, DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return false;

    char modulePath[MAX_PATH];
    if (!GetModuleFileNameExA(hProcess, hModule, modulePath, sizeof(modulePath))) {
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);

    // Check if it's a system module
    if (isSystemModule(modulePath)) {
        return true;
    }

    // Check digital signature
    if (!isModuleSigned(modulePath)) {
        return false;
    }

    // Check for suspicious paths
    std::vector<std::string> suspiciousPaths = {
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\"
    };

    std::string modulePathLower = modulePath;
    std::transform(modulePathLower.begin(), modulePathLower.end(), modulePathLower.begin(), ::tolower);

    for (const auto& suspiciousPath : suspiciousPaths) {
        if (modulePathLower.find(suspiciousPath) != std::string::npos) {
            return false;
        }
    }

    return true;
}

bool DllInjectionDetector::isModuleSigned(const std::string& modulePath) {
    WINTRUST_FILE_INFO fileData = {};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);

    std::wstring wModulePath(modulePath.begin(), modulePath.end());
    fileData.pcwszFilePath = wModulePath.c_str();
    fileData.hFile = nullptr;
    fileData.pgKnownSubject = nullptr;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.pwszURLReference = nullptr;
    winTrustData.dwUIContext = 0;
    winTrustData.pFile = &fileData;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    // Clean up
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    return (status == ERROR_SUCCESS);
}

bool DllInjectionDetector::detectManualMapping(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return false;

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T address = 0;

    while (VirtualQueryEx(hProcess, (PVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Look for executable memory regions that aren't backed by files
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Type == MEM_PRIVATE) &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            // Read the memory to check for PE headers
            std::vector<BYTE> buffer(std::min(mbi.RegionSize, static_cast<SIZE_T>(1024)));
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                // Check for PE signature (MZ header)
                if (bytesRead >= 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }

        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return false;
}

std::vector<DetectionResult> DllInjectionDetector::detectHooks(DWORD processId) {
    std::vector<DetectionResult> detections;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return detections;

    char processName[MAX_PATH];
    GetModuleBaseNameA(hProcess, nullptr, processName, sizeof(processName));

    // Get kernel32.dll base address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        CloseHandle(hProcess);
        return detections;
    }

    // Check common API functions for hooks
    std::vector<std::string> commonApis = {
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
        "VirtualAlloc", "VirtualProtect", "LoadLibraryA", "LoadLibraryW",
        "GetProcAddress", "CreateProcessA", "CreateProcessW"
    };

    for (const auto& apiName : commonApis) {
        FARPROC originalFunc = GetProcAddress(hKernel32, apiName.c_str());
        if (!originalFunc) continue;

        // Read the first few bytes of the function
        BYTE functionBytes[16];
        SIZE_T bytesRead;

        if (ReadProcessMemory(hProcess, originalFunc, functionBytes, sizeof(functionBytes), &bytesRead)) {
            // Check for common hook patterns (JMP, CALL, etc.)
            if (bytesRead >= 5) {
                // Check for JMP instruction (0xE9)
                if (functionBytes[0] == 0xE9) {
                    DetectionResult detection(
                        DetectionType::HOOK_DETECTION,
                        Severity::MEDIUM,
                        processName,
                        processId,
                        "API hook detected on " + apiName
                    );
                    detections.push_back(detection);
                    LOG_WARNING("API hook detected: " + apiName + " in process " + processName);
                }

                // Check for other hook patterns (PUSH + RET combination)
                if (functionBytes[0] == 0x68 && functionBytes[5] == 0xC3) { // PUSH + RET
                    DetectionResult detection(
                        DetectionType::HOOK_DETECTION,
                        Severity::MEDIUM,
                        processName,
                        processId,
                        "Trampoline hook detected on " + apiName
                    );
                    detections.push_back(detection);
                    LOG_WARNING("Trampoline hook detected: " + apiName + " in process " + processName);
                }
            }
        }
    }

    CloseHandle(hProcess);
    return detections;
}

std::vector<DetectionResult> DllInjectionDetector::detectSetWindowsHookEx() {
    std::vector<DetectionResult> detections;

    // Note: This is a simplified detection. Real implementation would need
    // to enumerate system-wide hooks, which requires more complex WinAPI calls
    // For now, we'll detect processes that have loaded hook-related DLLs

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return detections;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {
        do {
            auto modules = getCurrentModules(pe32.th32ProcessID);
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

            if (hProcess) {
                for (const auto& hModule : modules) {
                    char modulePath[MAX_PATH];
                    if (GetModuleFileNameExA(hProcess, hModule, modulePath, sizeof(modulePath))) {
                        std::string modulePathStr(modulePath);
                        std::transform(modulePathStr.begin(), modulePathStr.end(), modulePathStr.begin(), ::tolower);

                        // Check for hook-related keywords in module names
                        if (modulePathStr.find("hook") != std::string::npos ||
                            modulePathStr.find("inject") != std::string::npos ||
                            modulePathStr.find("overlay") != std::string::npos) {

                            // Convert TCHAR to std::string
                            std::string processName;
#ifdef UNICODE
                            int size = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
                            if (size > 0) {
                                std::vector<char> buffer(size);
                                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, buffer.data(), size, nullptr, nullptr);
                                processName = std::string(buffer.data());
                            }
#else
                            processName = std::string(pe32.szExeFile);
#endif

                            DetectionResult detection(
                                DetectionType::HOOK_DETECTION,
                                Severity::HIGH,
                                processName,
                                pe32.th32ProcessID,
                                "Suspicious hook-related module: " + modulePathStr
                            );
                            detections.push_back(detection);
                            LOG_WARNING("Hook-related module detected: " + modulePathStr);
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return detections;
}

bool DllInjectionDetector::isSystemModule(const std::string& modulePath) {
    std::string modulePathLower = modulePath;
    std::transform(modulePathLower.begin(), modulePathLower.end(), modulePathLower.begin(), ::tolower);

    std::vector<std::string> systemPaths = {
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\windows\\winsxs\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\"
    };

    for (const auto& systemPath : systemPaths) {
        if (modulePathLower.find(systemPath) == 0) {
            return true;
        }
    }

    return false;
}