#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pcap.h>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include <string>

namespace py = pybind11;

class WolfcapSniffer {
private:
    pcap_t* handle;
    std::atomic<bool> running;
    std::thread capture_thread;
    std::string device;
    py::object callback;

    static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        WolfcapSniffer* sniffer = reinterpret_cast<WolfcapSniffer*>(user);
        if (!sniffer->running) return;
        
        // Copy packet data
        std::string raw_bytes(reinterpret_cast<const char*>(packet), pkthdr->caplen);
        
        // We cannot call Python directly from this C thread without acquiring GIL
        // For simplicity in this implementation, we will acquire GIL here and call the callback.
        // In a true zero-copy design, we would push to a lockless ringbuffer and let Python pull.
        // But for drop-in Scapy replacement, we call the callback with the bytes.
        py::gil_scoped_acquire acquire;
        try {
            sniffer->callback(py::bytes(raw_bytes));
        } catch (...) {
            // Ignore Python errors during packet processing
        }
    }

    void capture_loop() {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(device.c_str(), 65536, 1, 100, errbuf);
        if (handle == nullptr) {
            // Attempt to resolve device name if it's not a direct WinPcap GUID
            pcap_if_t *alldevs;
            if (pcap_findalldevs(&alldevs, errbuf) == 0) {
                for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
                    if (d->description && device.find(d->description) != std::string::npos) {
                        handle = pcap_open_live(d->name, 65536, 1, 100, errbuf);
                        break;
                    }
                }
                pcap_freealldevs(alldevs);
            }
        }
        
        if (handle == nullptr) {
            return;
        }

        while (running) {
            pcap_dispatch(handle, 100, packet_handler, reinterpret_cast<u_char*>(this));
        }

        pcap_close(handle);
        handle = nullptr;
    }

public:
    WolfcapSniffer(const std::string& dev, py::object cb) : handle(nullptr), running(false), device(dev), callback(cb) {
    }

    ~WolfcapSniffer() {
        stop();
    }

    void start() {
        if (running) return;
        running = true;
        capture_thread = std::thread(&WolfcapSniffer::capture_loop, this);
    }

    void stop() {
        if (!running) return;
        running = false;
        if (capture_thread.joinable()) {
            capture_thread.join();
        }
    }
};

static std::vector<std::string> get_interfaces() {
    std::vector<std::string> devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
            if (d->description) {
                devices.push_back(d->description);
            } else {
                devices.push_back(d->name);
            }
        }
        pcap_freealldevs(alldevs);
    }
    return devices;
}

PYBIND11_MODULE(wolfcap, m) {
    m.doc() = "Native C++ High-Speed Packet Capture Engine for Wolfsniff";
    m.def("get_interfaces", &get_interfaces, "Get a list of available network interfaces");
    
    py::class_<WolfcapSniffer>(m, "WolfcapSniffer")
        .def(py::init<const std::string&, py::object>())
        .def("start", &WolfcapSniffer::start)
        .def("stop", &WolfcapSniffer::stop);
}
