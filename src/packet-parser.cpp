#include "packet-parser.h"
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace PacketParser {

    std::string bytes_to_ip(const uint8_t* bytes) {
        std::stringstream ss;
        ss << static_cast<int>(bytes[0]) << '.'
            << static_cast<int>(bytes[1]) << '.'
            << static_cast<int>(bytes[2]) << '.'
            << static_cast<int>(bytes[3]);
        return ss.str();
    }

    void process_file(
        const std::string& filename,
        uint64_t& total_packets,
        uint64_t& with_ipv4,
        uint64_t& without_ipv4,
        std::map<std::pair<std::string, std::string>, uint64_t>& ip_pair_counts
    ) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Error opening file: " + filename);
        }

        total_packets = 0;
        with_ipv4 = 0;
        without_ipv4 = 0;
        ip_pair_counts.clear();

        while (file) {
            uint8_t len_bytes[2];
            file.read(reinterpret_cast<char*>(len_bytes), 2);
            if (file.gcount() != 2) {
                break;
            }

            uint16_t pkt_len = (static_cast<uint16_t>(len_bytes[0]) << 8) | len_bytes[1];

            if (pkt_len < 14) {
                file.seekg(pkt_len, std::ios::cur);
                total_packets++;
                without_ipv4++;
                continue;
            }

            std::vector<uint8_t> packet(pkt_len);
            file.read(reinterpret_cast<char*>(packet.data()), pkt_len);
            if (static_cast<uint16_t>(file.gcount()) != pkt_len) {
                break;
            }

            total_packets++;

            uint16_t ether_type = (static_cast<uint16_t>(packet[12]) << 8) | packet[13];

            if (ether_type == 0x0800) {
                if (pkt_len < 34) {
                    without_ipv4++;
                }
                else {
                    with_ipv4++;
                    std::string src_ip = bytes_to_ip(&packet[26]);
                    std::string dst_ip = bytes_to_ip(&packet[30]);
                    ip_pair_counts[{src_ip, dst_ip}]++;
                }
            }
            else {
                without_ipv4++;
            }
        }
    }

    void print_statistics(
        uint64_t total_packets,
        uint64_t with_ipv4,
        uint64_t without_ipv4,
        const std::map<std::pair<std::string, std::string>, uint64_t>& ip_pair_counts
    ) {
        std::cout << "Packets processed: " << total_packets << '\n'
            << "Packets contains IPv4: " << with_ipv4 << '\n'
            << "Packets without IPv4: " << without_ipv4 << '\n';

        std::vector<std::pair<std::pair<std::string, std::string>, uint64_t>> sorted_pairs;
        sorted_pairs.reserve(ip_pair_counts.size());
        for (const auto& entry : ip_pair_counts) {
            sorted_pairs.push_back(entry);
        }

        std::sort(sorted_pairs.begin(), sorted_pairs.end(),
            [](const auto& a, const auto& b) {
                return a.second > b.second;
            });

        for (const auto& entry : sorted_pairs) {
            std::cout << entry.first.first << " -> "
                << entry.first.second << " "
                << entry.second << '\n';
        }
    }
}