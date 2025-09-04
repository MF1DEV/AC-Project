#include "MemoryScanner.h"
#include "../core/Logger.h"
#include <algorithm>  // Add this for std::min

MemoryScanner::MemoryScanner() {
    cheatSignatures = getDefaultSignatures();
    LOG_INFO("MemoryScanner initialized with " + std::to_string(cheatSignatures.size()) + " signatures");
}

MemoryScanner::~MemoryScanner() {
    LOG_INFO("MemoryScanner destroyed");
}

std::vector<DetectionResult> MemoryScanner::scanProcessMemory(DWORD processId) {
    std::lock_guard<std::mutex> lock(scannerMutex);
    std::vector<DetectionResult> detections;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        LOG_DEBUG("Failed to open process " + std::to_string(processId) + " for memory scanning");
        return detections;
    }

    char processName[MAX_PATH];
    GetModuleBaseNameA(hProcess, nullptr, processName, sizeof(processName));

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T address = 0;

    while (VirtualQueryEx(hProcess, (PVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && isExecutableRegion(mbi)) {
            // Scan this memory region for signatures
            for (size_t i = 0; i < cheatSignatures.size(); ++i) {
                if (scanMemoryRegion(hProcess, mbi.BaseAddress, mbi.RegionSize, cheatSignatures[i])) {
                    DetectionResult detection(
                        DetectionType::SIGNATURE_MATCH,
                        Severity::HIGH,
                        processName,
                        processId,
                        "Cheat signature found in memory at address 0x" +
                        std::to_string(reinterpret_cast<uintptr_t>(mbi.BaseAddress))
                    );

                    // Store signature index as evidence
                    detection.evidence.push_back(static_cast<uint8_t>(i));
                    detections.push_back(detection);

                    LOG_WARNING("Cheat signature " + std::to_string(i) + " found in process " + processName);
                }
            }
        }

        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);

    // Also check for code caves and memory patches
    auto codeCaveDetections = detectCodeCaves(processId);
    auto memoryPatchDetections = detectMemoryPatches(processId);

    detections.insert(detections.end(), codeCaveDetections.begin(), codeCaveDetections.end());
    detections.insert(detections.end(), memoryPatchDetections.begin(), memoryPatchDetections.end());

    return detections;
}

bool MemoryScanner::scanMemoryRegion(HANDLE hProcess, PVOID baseAddress, SIZE_T regionSize, const std::vector<BYTE>& signature) {
    if (signature.empty() || regionSize < signature.size()) return false;

    // Read memory in chunks to avoid large allocations
    const SIZE_T CHUNK_SIZE = 64 * 1024; // 64KB chunks
    SIZE_T totalRead = 0;

    std::vector<BYTE> buffer(CHUNK_SIZE + signature.size());
    std::vector<BYTE> overlap(signature.size() - 1, 0);

    while (totalRead < regionSize) {
        SIZE_T readSize = std::min(CHUNK_SIZE, regionSize - totalRead);  // Use std::min
        SIZE_T bytesRead;

        // Copy overlap from previous chunk
        if (totalRead > 0) {
            std::copy(overlap.begin(), overlap.end(), buffer.begin());
        }

        PVOID currentAddress = (PVOID)((uintptr_t)baseAddress + totalRead);
        if (!ReadProcessMemory(hProcess, currentAddress,
            buffer.data() + (totalRead > 0 ? overlap.size() : 0),
            readSize, &bytesRead)) {
            break;
        }

        SIZE_T searchSize = bytesRead + (totalRead > 0 ? overlap.size() : 0);

        // Search for signature in current chunk
        for (SIZE_T i = 0; i <= searchSize - signature.size(); ++i) {
            bool found = true;
            for (SIZE_T j = 0; j < signature.size(); ++j) {
                if (signature[j] != 0x00 && buffer[i + j] != signature[j]) { // 0x00 = wildcard
                    found = false;
                    break;
                }
            }
            if (found) return true;
        }

        // Save overlap for next iteration
        if (bytesRead >= signature.size() - 1) {
            std::copy(buffer.end() - (signature.size() - 1), buffer.end(), overlap.begin());
        }

        totalRead += bytesRead;
    }

    return false;
}

std::vector<DetectionResult> MemoryScanner::detectCodeCaves(DWORD processId) {
    std::vector<DetectionResult> detections;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return detections;

    char processName[MAX_PATH];
    GetModuleBaseNameA(hProcess, nullptr, processName, sizeof(processName));

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T address = 0;

    while (VirtualQueryEx(hProcess, (PVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Look for executable private memory (potential code caves)
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            // Read a sample of the memory
            std::vector<BYTE> sample(std::min(mbi.RegionSize, static_cast<SIZE_T>(1024)));  // Use std::min
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, sample.data(), sample.size(), &bytesRead)) {
                // Check for non-zero executable code (indicating injected code)
                bool hasCode = false;
                for (const auto& byte : sample) {
                    if (byte != 0x00 && byte != 0xCC) { // Not null or int3
                        hasCode = true;
                        break;
                    }
                }

                if (hasCode) {
                    DetectionResult detection(
                        DetectionType::MEMORY_MODIFICATION,
                        Severity::MEDIUM,
                        processName,
                        processId,
                        "Potential code cave detected at address 0x" +
                        std::to_string(reinterpret_cast<uintptr_t>(mbi.BaseAddress))
                    );
                    detections.push_back(detection);

                    LOG_WARNING("Code cave detected in process " + std::string(processName));
                }
            }
        }

        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return detections;
}

std::vector<DetectionResult> MemoryScanner::detectMemoryPatches(DWORD processId) {
    std::vector<DetectionResult> detections;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return detections;

    char processName[MAX_PATH];
    GetModuleBaseNameA(hProcess, nullptr, processName, sizeof(processName));

    // Get loaded modules to check their integrity
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
            char modulePath[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], modulePath, sizeof(modulePath))) {

                // Read the module's DOS header
                IMAGE_DOS_HEADER dosHeader;
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, hMods[i], &dosHeader, sizeof(dosHeader), &bytesRead)) {
                    // Basic integrity check - verify DOS signature
                    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                        DetectionResult detection(
                            DetectionType::MEMORY_MODIFICATION,
                            Severity::HIGH,
                            processName,
                            processId,
                            "Module header corruption detected: " + std::string(modulePath)
                        );
                        detections.push_back(detection);

                        LOG_ERROR("Module corruption detected: " + std::string(modulePath));
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);
    return detections;
}

bool MemoryScanner::isExecutableRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

std::vector<std::vector<BYTE>> MemoryScanner::getDefaultSignatures() {
    // Default cheat signatures (these are examples - real signatures would be more sophisticated)
    return {
        // Example aimbot signature pattern
        {0x89, 0x44, 0x24, 0x04, 0x8B, 0x44, 0x24, 0x08, 0x89, 0x44, 0x24, 0x08},

        // Example ESP signature pattern
        {0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x0A},

        // Example speed hack signature
        {0xDB, 0x05, 0x00, 0x00, 0x00, 0x00, 0xD9, 0x5C, 0x24, 0x04},

        // Common cheat engine signature
        {0x43, 0x68, 0x65, 0x61, 0x74, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65}, // "CheatEngine"

        // DLL injection signature (LoadLibrary call pattern)
        {0x68, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00}, // push addr; call LoadLibrary
    };
}

bool MemoryScanner::loadSignatures(const std::string& signaturesPath) {
    std::ifstream file(signaturesPath, std::ios::binary);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open signatures file: " + signaturesPath);
        return false;
    }

    cheatSignatures.clear();

    // Simple format: each line contains hex bytes separated by spaces
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue; // Skip comments

        std::vector<BYTE> signature;
        std::istringstream iss(line);
        std::string hexByte;

        while (iss >> hexByte) {
            try {
                unsigned int byte = std::stoul(hexByte, nullptr, 16);
                signature.push_back(static_cast<BYTE>(byte));
            }
            catch (const std::exception&) {
                LOG_WARNING("Invalid hex byte in signature: " + hexByte);
                break;
            }
        }

        if (!signature.empty()) {
            cheatSignatures.push_back(signature);
        }
    }

    file.close();
    LOG_INFO("Loaded " + std::to_string(cheatSignatures.size()) + " signatures from " + signaturesPath);
    return true;
}