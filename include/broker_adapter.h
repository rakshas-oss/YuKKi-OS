#pragma once

#include <string>
#include <vector>

namespace nvlink::broker {

struct BrokerTask {
    std::string task_id;
    std::string source;
    std::string destination;
    std::string kind;
    std::vector<double> payload;
};

struct BrokerResult {
    std::string task_id;
    std::string status;
    int gpu_id = -1;
    std::vector<double> result;
};

BrokerResult execute_broker_task(const BrokerTask& task);

} // namespace nvlink::broker
