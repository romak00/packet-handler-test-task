#include "packet-parser.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << '\n';
        return 1;
    }

    try {
        uint64_t total_packets;
        uint64_t with_ipv4;
        uint64_t without_ipv4;
        std::map<std::pair<std::string, std::string>, uint64_t> ip_pair_counts;

        PacketParser::process_file(
            argv[1],
            total_packets,
            with_ipv4,
            without_ipv4,
            ip_pair_counts
        );

        PacketParser::print_statistics(
            total_packets,
            with_ipv4,
            without_ipv4,
            ip_pair_counts
        );
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}