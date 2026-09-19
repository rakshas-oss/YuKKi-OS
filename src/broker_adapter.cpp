#include "broker_adapter.h"

#include <functional>
#include <string>
#include <vector>

#include "nvlink_placement.h"

namespace nvlink::broker {

static std::vector<double> run_gpu_work(const std::vector<double>& input, int gpu_id) {
    std::vector<double> out;
    out.reserve(input.size());
    for (double value : input) {
        out.push_back(value * 2.0);
    }
    (void)gpu_id;
    return out;
}

BrokerResult execute_broker_task(const BrokerTask& task) {
    nvlink::GpuTopology topo = nvlink::GpuTopology::detect();
    nvlink::Placer placer(topo, 32);

    const int home = placer.assign_home(static_cast<int>(std::hash<std::string>{}(task.task_id)));
    const int target_gpu = placer.place(home, [&](int gpu) {
        (void)gpu;
        return 0;
    });

    BrokerResult result;
    result.task_id = task.task_id;
    result.status = "ok";
    result.gpu_id = target_gpu;
    result.result = run_gpu_work(task.payload, target_gpu);
    return result;
}

} // namespace nvlink::broker
