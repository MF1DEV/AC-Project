#include "../include/Common.h"
#include "core/DetectionEngine.h"
#include "network/ReportSender.h"
#include "utils/WinUtils.h"
#include "utils/Crypto.h"
#include "core/Logger.h"

class AntiCheatClient {
private:
    std::unique_ptr<DetectionEngine> detectionEngine;
    std::unique_ptr<ReportSender> reportSender;
    std::string clientId;
    std::string webhookUrl;
    bool isRunning;

public:
    AntiCheatClient() : isRunning(false) {
        clientId = Crypto::generateClientId();

        // Load config
        loadConfiguration();

        // Initialize components
        detectionEngine = std::make_unique<DetectionEngine>();
        reportSender = std::make_unique<ReportSender>(webhookUrl, clientId);
    }

    bool initialize() {
        LOG_INFO("Initializing AntiCheat Client...");
        LOG_INFO("Client ID: " + clientId);
        LOG_INFO("System Info: " + WinUtils::getSystemInfo());

        // Check if running as administrator
        if (!WinUtils::isProcessElevated()) {
            LOG_WARNING("Process is not elevated - some detections may be limited");
        }

        // Enable debug privileges
        if (WinUtils::enableDebugPrivileges()) {
            LOG_INFO("Debug privileges enabled");
        }
        else {
            LOG_WARNING("Failed to enable debug privileges");
        }

        // Initialize detection engine
        if (!detectionEngine->initialize()) {
            LOG_ERROR("Failed to initialize detection engine");
            return false;
        }

        // Set detection callback
        detectionEngine->setDetectionCallback([this](const DetectionResult& detection) {
            onDetection(detection);
            });

        LOG_INFO("AntiCheat Client initialized successfully");
        return true;
    }

    void start() {
        if (isRunning) return;

        LOG_INFO("Starting AntiCheat Client...");
        isRunning = true;

        detectionEngine->start();

        LOG_INFO("AntiCheat Client started");
    }

    void stop() {
        if (!isRunning) return;

        LOG_INFO("Stopping AntiCheat Client...");
        isRunning = false;

        detectionEngine->stop();

        LOG_INFO("AntiCheat Client stopped");
    }

    void run() {
        start();

        LOG_INFO("Press 'q' to quit...");

        char input;
        while (std::cin >> input) {
            if (input == 'q' || input == 'Q') {
                break;
            }
            else if (input == 's' || input == 'S') {
                // Print statistics
                auto detections = detectionEngine->getRecentDetections();
                LOG_INFO("Recent detections: " + std::to_string(detections.size()));
            }
        }

        stop();
    }

private:
    void loadConfiguration() {
        std::ifstream configFile("config/config.json");
        if (configFile.is_open()) {
            try {
                json config;
                configFile >> config;

                webhookUrl = config.value("webhookUrl", "");

                if (webhookUrl.empty()) {
                    LOG_WARNING("No webhook URL configured");
                }

                LOG_INFO("Configuration loaded successfully");
            }
            catch (const std::exception& e) {
                LOG_ERROR("Failed to parse configuration: " + std::string(e.what()));
                webhookUrl = "";
            }
            configFile.close();
        }
        else {
            LOG_WARNING("Configuration file not found, using defaults");
            webhookUrl = "";
        }
    }

    void onDetection(const DetectionResult& detection) {
        // Send detection report to Discord webhook
        if (!webhookUrl.empty()) {
            if (!reportSender->sendDetectionReport(detection)) {
                LOG_ERROR("Failed to send detection report");
            }
        }

        // Additional actions can be added here (e.g., local alerts, game client notifications)
    }
};

int main() {
    try {
        // Set console title
        SetConsoleTitleA("AntiCheat Client - Phase 1");

        // Initialize logging
        Logger::getInstance().setLogLevel(LogLevel::INFO_LEVEL);
        LOG_INFO("=== AntiCheat Client Starting ===");

        // Create and initialize client
        AntiCheatClient client;
        if (!client.initialize()) {
            LOG_ERROR("Failed to initialize client");
            return 1;
        }

        // Run the client
        client.run();

        LOG_INFO("=== AntiCheat Client Shutting Down ===");
        return 0;

    }
    catch (const std::exception& e) {
        LOG_ERROR("Unhandled exception: " + std::string(e.what()));
        return 1;
    }
}