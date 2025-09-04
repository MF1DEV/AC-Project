#include "ReportSender.h"
#include "../core/Logger.h"

ReportSender::ReportSender(const std::string& webhook, const std::string& clientIdentifier)
    : webhookUrl(webhook), clientId(clientIdentifier) {
    LOG_INFO("ReportSender initialized with webhook: " + webhook);
}

ReportSender::~ReportSender() {
    LOG_INFO("ReportSender destroyed");
}

bool ReportSender::sendDetectionReport(const DetectionResult& detection) {
    std::lock_guard<std::mutex> lock(sendMutex);

    try {
        json reportJson = createDetectionJson(detection);
        std::string jsonData = reportJson.dump();

        return sendHttpPost(jsonData);
    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to send detection report: " + std::string(e.what()));
        return false;
    }
}

bool ReportSender::sendBulkReport(const std::vector<DetectionResult>& detections) {
    if (detections.empty()) return true;

    std::lock_guard<std::mutex> lock(sendMutex);

    try {
        json bulkReport;
        bulkReport["clientId"] = clientId;
        bulkReport["timestamp"] = getCurrentTimestamp();
        bulkReport["detectionCount"] = detections.size();

        json detectionsArray = json::array();
        for (const auto& detection : detections) {
            detectionsArray.push_back(createDetectionJson(detection));
        }
        bulkReport["detections"] = detectionsArray;

        std::string jsonData = bulkReport.dump();
        return sendHttpPost(jsonData);

    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to send bulk report: " + std::string(e.what()));
        return false;
    }
}

json ReportSender::createDetectionJson(const DetectionResult& detection) {
    json detectionJson;

    // Basic detection info
    detectionJson["clientId"] = clientId;
    detectionJson["timestamp"] = getCurrentTimestamp();
    detectionJson["processName"] = detection.processName;
    detectionJson["processId"] = detection.processId;
    detectionJson["description"] = detection.description;

    // Detection type
    std::string typeStr;
    switch (detection.type) {
    case DetectionType::PROCESS_INJECTION: typeStr = "PROCESS_INJECTION"; break;
    case DetectionType::DLL_INJECTION: typeStr = "DLL_INJECTION"; break;
    case DetectionType::MEMORY_MODIFICATION: typeStr = "MEMORY_MODIFICATION"; break;
    case DetectionType::HOOK_DETECTION: typeStr = "HOOK_DETECTION"; break;
    case DetectionType::SIGNATURE_MATCH: typeStr = "SIGNATURE_MATCH"; break;
    case DetectionType::BEHAVIORAL_ANOMALY: typeStr = "BEHAVIORAL_ANOMALY"; break;
    }
    detectionJson["detectionType"] = typeStr;

    // Severity
    std::string severityStr;
    switch (detection.severity) {
    case Severity::LOW: severityStr = "LOW"; break;
    case Severity::MEDIUM: severityStr = "MEDIUM"; break;
    case Severity::HIGH: severityStr = "HIGH"; break;
    case Severity::CRITICAL: severityStr = "CRITICAL"; break;
    }
    detectionJson["severity"] = severityStr;

    // Evidence data (base64 encoded)
    if (!detection.evidence.empty()) {
        detectionJson["evidence"] = encodeBase64(detection.evidence);
    }

    return detectionJson;
}

bool ReportSender::sendHttpPost(const std::string& jsonData) {
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;

    try {
        // Parse webhook URL
        std::wstring wWebhookUrl(webhookUrl.begin(), webhookUrl.end());
        URL_COMPONENTS urlComp = {};
        urlComp.dwStructSize = sizeof(urlComp);

        wchar_t hostName[256];
        wchar_t urlPath[1024];
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = sizeof(hostName) / sizeof(wchar_t);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(wchar_t);

        if (!WinHttpCrackUrl(wWebhookUrl.c_str(), 0, 0, &urlComp)) {
            LOG_ERROR("Failed to parse webhook URL");
            return false;
        }

        // Initialize WinHTTP
        hSession = WinHttpOpen(L"AntiCheatClient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            LOG_ERROR("Failed to initialize WinHTTP session");
            return false;
        }

        // Connect to server
        hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
        if (!hConnect) {
            LOG_ERROR("Failed to connect to server");
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Create request
        DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath, nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            LOG_ERROR("Failed to create HTTP request");
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Set headers
        std::wstring headers = L"Content-Type: application/json\r\n";
        WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

        // Send request
        std::wstring wJsonData(jsonData.begin(), jsonData.end());
        BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)jsonData.c_str(), jsonData.length(),
            jsonData.length(), 0);

        if (!result) {
            LOG_ERROR("Failed to send HTTP request");
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Receive response
        result = WinHttpReceiveResponse(hRequest, nullptr);
        if (!result) {
            LOG_ERROR("Failed to receive HTTP response");
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Check status code
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize,
            WINHTTP_NO_HEADER_INDEX);

        // Clean up
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (statusCode >= 200 && statusCode < 300) {
            LOG_INFO("Detection report sent successfully (Status: " + std::to_string(statusCode) + ")");
            return true;
        }
        else {
            LOG_WARNING("HTTP request failed with status: " + std::to_string(statusCode));
            return false;
        }

    }
    catch (const std::exception& e) {
        LOG_ERROR("Exception in sendHttpPost: " + std::string(e.what()));

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return false;
    }
}

std::string ReportSender::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string ReportSender::encodeBase64(const std::vector<uint8_t>& data) {
    const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;

    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (result.size() % 4) {
        result.push_back('=');
    }

    return result;
}