#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <iostream>

namespace PacketParser {

    std::string bytes_to_ip(const uint8_t* bytes);

    void process_file(
        const std::string& filename,
        uint64_t& total_packets,
        uint64_t& with_ipv4,
        uint64_t& without_ipv4,
        std::map<std::pair<std::string, std::string>, uint64_t>& ip_pair_counts
    );

    void print_statistics(
        uint64_t total_packets,
        uint64_t with_ipv4,
        uint64_t without_ipv4,
        const std::map<std::pair<std::string, std::string>, uint64_t>& ip_pair_counts
    );

}