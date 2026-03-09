/**
 * NetworkAPI plugin to implement a host blocker (mainly SNI)
 *
 * @note This plugin uses a O(n) complexity, that means it is not fast enough for high-performance applications, network perfomance/speed might degrade
 *
 * @license Apache 2.0
 */

#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#include "CCommon.hxx"
#include "NetworkAPI.hxx"
#include "CForwards.hxx"

#include "SDK/json.hpp"

std::string global_plugin_name = "NetworkAPI_HostBlocker";
std::string global_plugin_version = "1.0.0";
std::string global_plugin_author = "NetworkAPI Development Team";

using json = nlohmann::json;

std::vector<std::string> global_host_table;

bool global_allow_mode = false;

bool MatchesSNI(const unsigned char* data, size_t data_length, const std::string& host)
{
    if (data_length < 5 || data[0] != 0x16)
        return false;

    if (data_length < 6 || data[5] != 0x01)
        return false;

    size_t current = 5 + 4 + 2 + 32;
    
    if (current >= data_length)
        return false;

    uint8_t session_identification_length = data[current];

    current += 1 + session_identification_length;

    if (current + 2 > data_length)
        return false;

    uint16_t cipher_length = (data[current] << 8) | data[current + 1];

    current += 2 + cipher_length;

    if (current + 1 > data_length)
        return false;

    uint8_t compression_methods_length = data[current];

    current += 1 + compression_methods_length;

    if (current + 2 > data_length)
        return false;

    uint16_t extensions_length = (data[current] << 8) | data[current + 1];

    current += 2;

    size_t extensions_end = current + extensions_length;

    if (extensions_end > data_length)
        return false;

    while (current + 4 <= extensions_end)
    {
        uint16_t extension_type = (data[current] << 8) | data[current + 1];
        uint16_t extension_length = (data[current + 2] << 8) | data[current + 3];

        current += 4;

        if (extension_type == 0)
        {
            if (current + extension_length > extensions_end)
                return false;

            size_t sni_pointer = current + 2; 

            if (sni_pointer + 3 > current + extension_length)
                return false;
            
            uint16_t name_length = (data[sni_pointer + 1] << 8) | data[sni_pointer + 2];

            if (sni_pointer + 3 + name_length > current + extension_length)
                return false;

            std::string sni(reinterpret_cast<const char*>(&data[sni_pointer + 3]), name_length);

            return sni == host;
        }

        current += extension_length;
    }

    return false;
}

void LoadConfiguration()
{
    std::ifstream input_file_stream("NetworkAPI_HostBlocker_Configuration.json");

    if (!input_file_stream)
    {
        std::cerr << CCommon_ConsoleText_Red << "[NetworkAPI:Plugin/Error] [" << global_plugin_name << "] Error loading configuration file" << CCommon_ConsoleText_Default << std::endl;

        return;
    }

    json json_root_object;

    input_file_stream >> json_root_object;

    if (json_root_object.contains("networkapi_hostblocker"))
    {
        global_allow_mode = json_root_object["networkapi_hostblocker"]["allow_mode"].get<bool>();

        auto &json_array_host_table = json_root_object["networkapi_hostblocker"]["host_table"];

        for (const auto &json_array_host_table_item: json_array_host_table)
            global_host_table.push_back(json_array_host_table_item);
    }

    else
    {
        std::cerr << CCommon_ConsoleText_Red << "[NetworkAPI:Plugin/Error] [" << global_plugin_name << "] Error loading configuration file" << CCommon_ConsoleText_Default << std::endl;

        return;
    }
}

CForwards_PluginExport CForwards_ForwardResult On_PluginInit()
{
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " On_PluginInit" << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Name: " << global_plugin_name << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Version: " << global_plugin_version << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Author: " << global_plugin_author << std::endl;

    LoadConfiguration();

    return CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PluginEnd()
{
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " On_PluginEnd" << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Name: " << global_plugin_name << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Version: " << global_plugin_version << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Author: " << global_plugin_author << std::endl;

    return CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PacketReceive_IPv4(NetworkAPI_PacketMetadata *packet_metadata, unsigned char *packet, int *packet_length, unsigned char *data, int *data_length, NetworkAPI_PacketHeader_IPv4 *ipv4_header, NetworkAPI_PacketHeader_TCP *tcp_header, NetworkAPI_PacketHeader_UDP *udp_header, NetworkAPI_PacketHeader_ICMP *icmp_header)
{
    if (tcp_header == nullptr)
        return CForwards_ForwardResult::Forward_Ignored;

    if (data == nullptr || data_length == 0)
        return CForwards_ForwardResult::Forward_Ignored;

    if (*data_length < 5 || data[0] != 0x16)
        return CForwards_ForwardResult::Forward_Ignored;

    if (*data_length < 6 || data[5] != 0x01)
        return CForwards_ForwardResult::Forward_Ignored;

    for (const auto &host : global_host_table)
    {
        if (MatchesSNI(data, *data_length, host))
        {
            if (global_allow_mode)
                return CForwards_ForwardResult::Forward_Ignored;

            else
                return CForwards_ForwardResult::Forward_Supersede;
        }
    }

    return global_allow_mode ? CForwards_ForwardResult::Forward_Supersede : CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PacketReceive_IPv6(NetworkAPI_PacketMetadata *packet_metadata, unsigned char *packet, int *packet_length, unsigned char *data, int *data_length, NetworkAPI_PacketHeader_IPv6 *ipv6_header, NetworkAPI_PacketHeader_TCP *tcp_header, NetworkAPI_PacketHeader_UDP *udp_header, NetworkAPI_PacketHeader_ICMPv6 *icmpv6_header)
{
    if (tcp_header == nullptr)
        return CForwards_ForwardResult::Forward_Ignored;

    if (data == nullptr || data_length == 0)
        return CForwards_ForwardResult::Forward_Ignored;

    if (*data_length < 5 || data[0] != 0x16)
        return CForwards_ForwardResult::Forward_Ignored;

    if (*data_length < 6 || data[5] != 0x01)
        return CForwards_ForwardResult::Forward_Ignored;

    for (const auto &host : global_host_table)
    {
        if (MatchesSNI(data, *data_length, host))
        {
            if (global_allow_mode)
                return CForwards_ForwardResult::Forward_Ignored;

            else
                return CForwards_ForwardResult::Forward_Supersede;
        }
    }

    return global_allow_mode ? CForwards_ForwardResult::Forward_Supersede : CForwards_ForwardResult::Forward_Ignored;
}
