#pragma once
#include "../../include/Common.h"

class ProcessScanner {
private:
    std::vector<ProcessInfo> cachedProcesses;
    std::mutex processMutex;

public:
    ProcessScanner();
    ~ProcessScanner();

    std::vector<ProcessInfo> scanProcesses();
    bool verifyProcessSignature(const std::string& executablePath);
    std::vector<HMODULE> getProcessModules(DWORD processId);
    std::string getProcessPath(DWORD processId);
    std::vector<DetectionResult> detectSuspiciousProcesses();

private:
    bool isProcessSuspicious(const ProcessInfo& process);
    bool isKnownCheatProcess(const std::string& processName);
    bool hasDebuggerAttached(DWORD processId);
    std::vector<std::string> loadCheatSignatures();
};