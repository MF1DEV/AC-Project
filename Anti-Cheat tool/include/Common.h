#pragma once

// Windows headers - order matters for proper compilation
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <winhttp.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <lmcons.h>
#include <intrin.h>
#include <sddl.h>
#include <ntstatus.h>

// Standard C++ headers
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <thread>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <atomic>
#include <functional>

// JSON library
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Undefine Windows ERROR macro to avoid conflicts
#ifdef ERROR
#undef ERROR
#endif

// Detection types
enum class DetectionType {
    PROCESS_INJECTION,
    DLL_INJECTION,
    MEMORY_MODIFICATION,
    HOOK_DETECTION,
    SIGNATURE_MATCH,
    BEHAVIORAL_ANOMALY
};

// Detection severity levels
enum class Severity {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Detection result structure
struct DetectionResult {
    DetectionType type;
    Severity severity;
    std::string processName;
    DWORD processId;
    std::string description;
    std::vector<uint8_t> evidence;
    std::chrono::system_clock::time_point timestamp;

    // Constructor with all required parameters
    DetectionResult(DetectionType t, Severity s, const std::string& pName, DWORD pId, const std::string& desc)
        : type(t), severity(s), processName(pName), processId(pId), description(desc),
        timestamp(std::chrono::system_clock::now()) {
    }
};

// Process information structure
struct ProcessInfo {
    DWORD processId;
    std::string processName;
    std::string executablePath;
    HANDLE processHandle;
    std::vector<HMODULE> loadedModules;
    bool isSigned;

    // Constructor with required parameters
    ProcessInfo(DWORD pid, const std::string& name)
        : processId(pid), processName(name), processHandle(nullptr), isSigned(false) {
    }

    // Destructor to clean up handle
    ~ProcessInfo() {
        if (processHandle && processHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(processHandle);
            processHandle = nullptr;
        }
    }

    // Copy constructor
    ProcessInfo(const ProcessInfo& other)
        : processId(other.processId), processName(other.processName),
        executablePath(other.executablePath), processHandle(nullptr),
        loadedModules(other.loadedModules), isSigned(other.isSigned) {
    }

    // Assignment operator
    ProcessInfo& operator=(const ProcessInfo& other) {
        if (this != &other) {
            // Clean up existing handle
            if (processHandle && processHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(processHandle);
            }

            processId = other.processId;
            processName = other.processName;
            executablePath = other.executablePath;
            processHandle = nullptr; // Don't copy handle
            loadedModules = other.loadedModules;
            isSigned = other.isSigned;
        }
        return *this;
    }

    // Move constructor
    ProcessInfo(ProcessInfo&& other) noexcept
        : processId(other.processId), processName(std::move(other.processName)),
        executablePath(std::move(other.executablePath)), processHandle(other.processHandle),
        loadedModules(std::move(other.loadedModules)), isSigned(other.isSigned) {
        other.processHandle = nullptr;
    }

    // Move assignment operator
    ProcessInfo& operator=(ProcessInfo&& other) noexcept {
        if (this != &other) {
            // Clean up existing handle
            if (processHandle && processHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(processHandle);
            }

            processId = other.processId;
            processName = std::move(other.processName);
            executablePath = std::move(other.executablePath);
            processHandle = other.processHandle;
            loadedModules = std::move(other.loadedModules);
            isSigned = other.isSigned;

            other.processHandle = nullptr;
        }
        return *this;
    }
};

// Constants
constexpr size_t MAX_PROCESS_NAME = 260;
constexpr size_t MAX_PATH_LENGTH = 32767;
constexpr int SCAN_INTERVAL_MS = 5000; // 5 seconds

// NT API function definitions (missing from standard headers)
extern "C" {
    NTSTATUS NTAPI NtQueryInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
}