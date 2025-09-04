#pragma once
#include "../../include/Common.h"

class MemoryScanner {
private:
    std::vector<std::vector<BYTE>> cheatSignatures;
    std::mutex scannerMutex;

public:
    MemoryScanner();
    ~MemoryScanner();

    std::vector<DetectionResult> scanProcessMemory(DWORD processId);
    bool loadSignatures(const std::string& signaturesPath);
    std::vector<DetectionResult> detectCodeCaves(DWORD processId);
    std::vector<DetectionResult> detectMemoryPatches(DWORD processId);

private:
    bool scanMemoryRegion(HANDLE hProcess, PVOID baseAddress, SIZE_T regionSize, const std::vector<BYTE>& signature);
    std::vector<PVOID> findPattern(HANDLE hProcess, PVOID startAddress, SIZE_T searchSize, const std::vector<BYTE>& pattern);
    bool isExecutableRegion(const MEMORY_BASIC_INFORMATION& mbi);
    std::vector<std::vector<BYTE>> getDefaultSignatures();
};