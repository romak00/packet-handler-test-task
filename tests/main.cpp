#include "packet-parser.h"
#include "gtest/gtest.h"
#include <fstream>
#include <filesystem>
#include <vector>
#include <cstdint>
#include <map>

class PacketParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir = std::filesystem::temp_directory_path() / "packet_parser_tests";
        std::filesystem::create_directories(test_dir);
    }

    void TearDown() override {
        std::filesystem::remove_all(test_dir);
    }

    std::vector<uint8_t> create_test_packet(
        uint16_t length,
        uint16_t ether_type,
        const std::vector<uint8_t>& src_ip,
        const std::vector<uint8_t>& dst_ip
    ) {
        std::vector<uint8_t> packet(length, 0);

        if (length >= 14) {
            packet[12] = static_cast<uint8_t>(ether_type >> 8);
            packet[13] = static_cast<uint8_t>(ether_type & 0xFF);
        }

        if (length >= 34 && ether_type == 0x0800) {
            if (src_ip.size() == 4) {
                std::copy(src_ip.begin(), src_ip.end(), packet.begin() + 26);
            }
            if (dst_ip.size() == 4) {
                std::copy(dst_ip.begin(), dst_ip.end(), packet.begin() + 30);
            }
        }

        return packet;
    }

    std::vector<uint8_t> empty() {
        return {};
    }

    std::vector<uint8_t> valid_ipv4() {
        const std::vector<uint8_t> length = { 0x00, 0x3C };

        auto packet = create_test_packet(
            60,
            0x0800,
            { 192, 168, 1, 1 },
            { 10, 0, 0, 1 }
        );

        std::vector<uint8_t> result;
        result.insert(result.end(), length.begin(), length.end());
        result.insert(result.end(), packet.begin(), packet.end());
        return result;
    }

    std::vector<uint8_t> non_ipv4() {
        const std::vector<uint8_t> length = { 0x00, 0x0E };

        auto packet = create_test_packet(14, 0x0806, {}, {});

        std::vector<uint8_t> result;
        result.insert(result.end(), length.begin(), length.end());
        result.insert(result.end(), packet.begin(), packet.end());
        return result;
    }

    std::vector<uint8_t> corrupted_small() {
        return { 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
    }

    std::vector<uint8_t> multiple_packets() {
        auto pkt1 = valid_ipv4();
        auto pkt2 = non_ipv4();

        std::vector<uint8_t> result;
        result.insert(result.end(), pkt1.begin(), pkt1.end());
        result.insert(result.end(), pkt2.begin(), pkt2.end());
        return result;
    }

    std::string create_test_file(const std::vector<uint8_t>& data) {
        auto path = test_dir / "test.bin";
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return path.string();
    }

    std::filesystem::path test_dir;
};

TEST_F(PacketParserTest, BytesToIp) {
    const uint8_t bytes[] = { 192, 168, 1, 1 };
    EXPECT_EQ(PacketParser::bytes_to_ip(bytes), "192.168.1.1");
}

TEST_F(PacketParserTest, EmptyFile) {
    auto file = create_test_file(this->empty());

    uint64_t total, with_ip, without_ip;
    std::map<std::pair<std::string, std::string>, uint64_t> ip_pairs;

    EXPECT_NO_THROW(PacketParser::process_file(file, total, with_ip, without_ip, ip_pairs));
    EXPECT_EQ(total, 0);
    EXPECT_EQ(with_ip, 0);
    EXPECT_EQ(without_ip, 0);
    EXPECT_TRUE(ip_pairs.empty());
}

TEST_F(PacketParserTest, ValidIPv4) {
    auto file = create_test_file(this->valid_ipv4());

    uint64_t total, with_ip, without_ip;
    std::map<std::pair<std::string, std::string>, uint64_t> ip_pairs;

    PacketParser::process_file(file, total, with_ip, without_ip, ip_pairs);

    EXPECT_EQ(total, 1);
    EXPECT_EQ(with_ip, 1);
    EXPECT_EQ(without_ip, 0);
    EXPECT_EQ(ip_pairs.size(), 1);
    auto p = std::make_pair<std::string, std::string>("192.168.1.1", "10.0.0.1");
    EXPECT_EQ(ip_pairs[p], 1);
}

TEST_F(PacketParserTest, NonIPv4) {
    auto file = create_test_file(this->non_ipv4());

    uint64_t total, with_ip, without_ip;
    std::map<std::pair<std::string, std::string>, uint64_t> ip_pairs;

    PacketParser::process_file(file, total, with_ip, without_ip, ip_pairs);

    EXPECT_EQ(total, 1);
    EXPECT_EQ(with_ip, 0);
    EXPECT_EQ(without_ip, 1);
    EXPECT_TRUE(ip_pairs.empty());
}

TEST_F(PacketParserTest, CorruptedSmallPacket) {
    auto file = create_test_file(this->corrupted_small());

    uint64_t total, with_ip, without_ip;
    std::map<std::pair<std::string, std::string>, uint64_t> ip_pairs;

    PacketParser::process_file(file, total, with_ip, without_ip, ip_pairs);

    EXPECT_EQ(total, 1);
    EXPECT_EQ(with_ip, 0);
    EXPECT_EQ(without_ip, 1);
    EXPECT_TRUE(ip_pairs.empty());
}

TEST_F(PacketParserTest, MultiplePackets) {
    auto file = create_test_file(this->multiple_packets());

    uint64_t total, with_ip, without_ip;
    std::map<std::pair<std::string, std::string>, uint64_t> ip_pairs;

    PacketParser::process_file(file, total, with_ip, without_ip, ip_pairs);

    EXPECT_EQ(total, 2);
    EXPECT_EQ(with_ip, 1);
    EXPECT_EQ(without_ip, 1);
    EXPECT_EQ(ip_pairs.size(), 1);
    auto p = std::make_pair<std::string, std::string>("192.168.1.1", "10.0.0.1");
    EXPECT_EQ(ip_pairs[p], 1);
}

TEST_F(PacketParserTest, FileNotFound) {
    uint64_t total_packets = 0, with_ipv4 = 0, without_ipv4 = 0;
    std::map<std::pair<std::string, std::string>, uint64_t> ip_pairs;
    EXPECT_THROW(
        PacketParser::process_file("nonexistent_file",
            total_packets, with_ipv4, without_ipv4,
            ip_pairs),
        std::runtime_error
    );
}

TEST_F(PacketParserTest, IncompletePacket) {
    std::vector<uint8_t> data = {
        0x00, 0x0A,
        0x01, 0x02, 0x03, 0x04, 0x05
    };

    auto file = create_test_file(data);

    uint64_t total, with_ip, without_ip;
    std::map<std::pair<std::string, std::string>, uint64_t> ip_pairs;

    PacketParser::process_file(file, total, with_ip, without_ip, ip_pairs);

    EXPECT_EQ(total, 1);
    EXPECT_EQ(with_ip, 0);
    EXPECT_EQ(without_ip, 1);
    EXPECT_TRUE(ip_pairs.empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}