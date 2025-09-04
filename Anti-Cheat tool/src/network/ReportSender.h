#pragma once
#include "../../include/Common.h"

class ReportSender {
private:
    std::string webhookUrl;
    std::string clientId;
    std::mutex sendMutex;

public:
    ReportSender(const std::string& webhook, const std::string& clientIdentifier);
    ~ReportSender();

    bool sendDetectionReport(const DetectionResult& detection);
    bool sendBulkReport(const std::vector<DetectionResult>& detections);

private:
    json createDetectionJson(const DetectionResult& detection);
    bool sendHttpPost(const std::string& jsonData);
    std::string getCurrentTimestamp();
    std::string encodeBase64(const std::vector<uint8_t>& data);
};