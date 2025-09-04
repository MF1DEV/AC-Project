#include "ProcessScanner.h"
#include "../core/Logger.h"

ProcessScanner::ProcessScanner() {
    LOG_INFO("ProcessScanner initialized");
}

ProcessScanner::~ProcessScanner() {
    LOG_INFO("ProcessScanner destroyed");
}

std::vector<ProcessInfo> ProcessScanner::scanProcesses() {
    std::lock_guard<std::mutex> lock(processMutex);
    std::vector<ProcessInfo> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to create process snapshot");
        return processes;
    }

    PROCESSENTRY32 pe32;  // Use PROCESSENTRY32 (Unicode version)
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {  // Use Process32First (Unicode version)
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

            ProcessInfo processInfo(pe32.th32ProcessID, processName);
            processInfo.executablePath = getProcessPath(pe32.th32ProcessID);
            processInfo.isSigned = verifyProcessSignature(processInfo.executablePath);
            processInfo.loadedModules = getProcessModules(pe32.th32ProcessID);

            // Open process handle for further analysis
            processInfo.processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pe32.th32ProcessID
            );

            processes.push_back(std::move(processInfo));

        } while (Process32Next(snapshot, &pe32));  // Use Process32Next (Unicode version)
    }

    CloseHandle(snapshot);
    cachedProcesses = std::move(processes);

    LOG_DEBUG("Scanned " + std::to_string(cachedProcesses.size()) + " processes");
    return cachedProcesses;
}

bool ProcessScanner::verifyProcessSignature(const std::string& executablePath) {
    if (executablePath.empty()) return false;

    WINTRUST_FILE_INFO fileData = {};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);

    // Convert string to wstring
    std::wstring wPath(executablePath.begin(), executablePath.end());
    fileData.pcwszFilePath = wPath.c_str();
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

std::vector<HMODULE> ProcessScanner::getProcessModules(DWORD processId) {
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

std::string ProcessScanner::getProcessPath(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return "";

    char path[MAX_PATH_LENGTH];
    DWORD pathSize = MAX_PATH_LENGTH;

    if (QueryFullProcessImageNameA(hProcess, 0, path, &pathSize)) {
        CloseHandle(hProcess);
        return std::string(path);
    }

    CloseHandle(hProcess);
    return "";
}

std::vector<DetectionResult> ProcessScanner::detectSuspiciousProcesses() {
    std::vector<DetectionResult> detections;
    auto processes = scanProcesses();

    for (const auto& process : processes) {
        if (isProcessSuspicious(process)) {
            DetectionResult detection(
                DetectionType::PROCESS_INJECTION,
                Severity::HIGH,
                process.processName,
                process.processId,
                "Suspicious process detected: " + process.processName
            );
            detections.push_back(detection);

            LOG_WARNING("Suspicious process detected: " + process.processName + " (PID: " + std::to_string(process.processId) + ")");
        }

        if (hasDebuggerAttached(process.processId)) {
            DetectionResult detection(
                DetectionType::BEHAVIORAL_ANOMALY,
                Severity::CRITICAL,
                process.processName,
                process.processId,
                "Debugger attached to process: " + process.processName
            );
            detections.push_back(detection);

            LOG_ERROR("Debugger detected on process: " + process.processName);
        }
    }

    return detections;
}

bool ProcessScanner::isProcessSuspicious(const ProcessInfo& process) {
    // Check if it's a known cheat process
    if (isKnownCheatProcess(process.processName)) {
        return true;
    }

    // Check if unsigned executable
    if (!process.isSigned && !process.executablePath.empty()) {
        // Allow some common unsigned processes
        std::vector<std::string> allowedUnsigned = {
            "notepad.exe", "cmd.exe", "powershell.exe"
        };

        bool isAllowed = false;
        for (const auto& allowed : allowedUnsigned) {
            if (process.processName.find(allowed) != std::string::npos) {
                isAllowed = true;
                break;
            }
        }

        if (!isAllowed) {
            LOG_DEBUG("Unsigned process detected: " + process.processName);
            return true;
        }
    }

    // Check for suspicious paths
    std::vector<std::string> suspiciousPaths = {
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\"
    };

    std::string lowerPath = process.executablePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

    for (const auto& suspiciousPath : suspiciousPaths) {
        if (lowerPath.find(suspiciousPath) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool ProcessScanner::isKnownCheatProcess(const std::string& processName) {
    auto cheatSignatures = loadCheatSignatures();

    std::string lowerProcessName = processName;
    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);

    for (const auto& signature : cheatSignatures) {
        if (lowerProcessName.find(signature) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool ProcessScanner::hasDebuggerAttached(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return false;

    // Check if BeingDebugged flag is set in PEB
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr
    );

    if (NT_SUCCESS(status) && pbi.PebBaseAddress) {
        PEB peb;
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
            CloseHandle(hProcess);
            return peb.BeingDebugged != 0;
        }
    }

    CloseHandle(hProcess);
    return false;
}

std::vector<std::string> ProcessScanner::loadCheatSignatures() {
    std::vector<std::string> signatures;
    std::ifstream file("signatures/known_cheats.db");

    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty() && line[0] != '#') { // Skip comments
                signatures.push_back(line);
            }
        }
        file.close();
    }
    else {
        // Default signatures if file doesn't exist
        signatures = {
            "cheat", "hack", "inject", "trainer", "bot", "aimbot", "esp", "wallhack",
            "speedhack", "norecoil", "triggerbot", "radar", "internal", "external",
            "cheatengine", "artmoney", "gameguardian"
        };

        LOG_WARNING("Could not load cheat signatures database, using defaults");
    }

    return signatures;
}