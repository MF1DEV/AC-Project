#pragma once
#include "../../include/Common.h"

class DllInjectionDetector {
private:
    std::unordered_map<DWORD, std::vector<HMODULE>> previousModules;
    std::mutex detectorMutex;

public:
    DllInjectionDetector();
    ~DllInjectionDetector();

    std::vector<DetectionResult> detectInjectedDlls();
    std::vector<DetectionResult> detectHooks(DWORD processId);
    bool isModuleLegitimate(HMODULE hModule, DWORD processId);

private:
    std::vector<HMODULE> getCurrentModules(DWORD processId);
    bool isModuleSigned(const std::string& modulePath);
    std::vector<DetectionResult> analyzeNewModules(DWORD processId, const std::vector<HMODULE>& newModules);
    bool detectManualMapping(DWORD processId);
    std::vector<DetectionResult> detectSetWindowsHookEx();
    bool isSystemModule(const std::string& modulePath);
};