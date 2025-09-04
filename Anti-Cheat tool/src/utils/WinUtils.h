#pragma once
#include "../../include/Common.h"

class WinUtils {
public:
    static std::string getSystemInfo();
    static std::string getCurrentUserName();
    static std::string getComputerName();
    static std::string getMachineGuid();
    static bool isProcessElevated();
    static bool enableDebugPrivileges();
    static std::vector<std::string> getRunningServices();
    static bool isVirtualMachine();

private:
    static std::string readRegistryString(HKEY hKey, const std::string& subKey, const std::string& valueName);
};