#include <compartment.h>
#include <fail-simulator-on-error.h>

#include <debug.hh>
#include <locks.hh>
#include <timeout.hh>

#include "ethernet.hh"

using Debug = ConditionalDebug<true, "Ethernet harness">;

// ============================
// Enumerations
// ============================

// EtherType Enumeration
enum class EtherType : uint16_t
{
    VLAN = 0x8100,
    QinQ = 0x88A8,
    ARP = 0x0806,
    IPv6 = 0x86DD
};

// ProtocolType Enumeration for ARP
enum class ProtocolType : uint16_t
{
    IPv4 = 0x0800
};

// ICMPv6 Option Types Enumeration
enum class ICMPv6OptionType : uint8_t
{
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    PrefixInformation = 3
};

// ICMPv6 Message Types Enumeration
enum class ICMPv6Type : uint8_t
{
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    RouterSolicitation = 133,
    RouterAdvertisement = 134
};

// ARP Opcode Enumeration
enum class ARPOpcode : uint16_t
{
    Request = 1,
    Reply = 2
};

// ============================
// Global Constants
// ============================

// Ethernet Constants
constexpr size_t EthernetHeaderLength = 14;

// VLAN Constants
constexpr size_t VlanHeaderLength = 4;
constexpr size_t MaxVlanTags = 4;

// ICMPv6 Next Header Value
constexpr uint8_t ICMPv6NextHeader = 58;

// ICMPv6 Option Lengths
constexpr size_t ICMPv6OptionLengthSourceLinkLayerAddress = 8;
constexpr size_t ICMPv6OptionLengthTargetLinkLayerAddress = 8;
constexpr size_t ICMPv6OptionLengthPrefixInformation = 32;
constexpr size_t ICMPv6OptionMaxLength = 40;

// ICMPv6 Message Lengths
constexpr size_t NeighborSolicitationMessageLength = 24;
constexpr size_t NeighborAdvertisementMessageLength = 24;
constexpr size_t RouterSolicitationMessageLength = 16;
constexpr size_t RouterAdvertisementMessageLength = 16;

// IPv6 Constants
constexpr size_t IPv6HeaderLength = 40;

// ARP Constants
constexpr size_t ARPPayloadLength = 28;

// ============================
// Endian Conversion Functions
// ============================

// Converts a 32-bit value from network byte order to host byte order
uint32_t constexpr ntohl(uint32_t value)
{
#ifdef __LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value; // do nothing.
#endif
}

// Converts a 16-bit value from network byte order to host byte order
uint16_t constexpr ntohs(uint16_t value)
{
#ifdef __LITTLE_ENDIAN__
    return __builtin_bswap16(value);
#else
    return value; // do nothing.
#endif
}

// ============================
// ICMPv6 Option Parsing
// ============================

static bool parse_icmpv6_options(const uint8_t *frameData, size_t frameLength, size_t offset, size_t end)
{
    constexpr size_t optionLengthUnit = 8; // Number of bytes per unit

    while (offset < end)
    {
        if (offset + 2 > end)
        {
            Debug::log("ICMPv6 Option truncated.");
            return false;
        }

        uint8_t optionType = frameData[offset];
        uint8_t optionLength = frameData[offset + 1]; // Length in 8-octet units
        size_t optionTotalLength = static_cast<size_t>(optionLength) * optionLengthUnit;

        if (optionLength == 0 || optionTotalLength > ICMPv6OptionMaxLength || offset + optionTotalLength > end)
        {
            Debug::log("ICMPv6 Option truncated or exceeds maximum allowed length.");
            return false;
        }

        if (optionType == static_cast<uint8_t>(ICMPv6OptionType::SourceLinkLayerAddress)) // Source Link-Layer
                                                                                          // Address
        {
            if (optionTotalLength < ICMPv6OptionLengthSourceLinkLayerAddress)
            {
                Debug::log("Invalid Source Link-Layer Address option length.");
                return false;
            }
            uint8_t sourceMacAddressBytes[6];
            std::memcpy(sourceMacAddressBytes, frameData + offset + 2, 6);

            Debug::log("ICMPv6 Source Link-Layer Address={}:{}:{}:{}:{}:{}", sourceMacAddressBytes[0],
                       sourceMacAddressBytes[1], sourceMacAddressBytes[2], sourceMacAddressBytes[3],
                       sourceMacAddressBytes[4], sourceMacAddressBytes[5]);
        }
        else if (optionType ==
                 static_cast<uint8_t>(ICMPv6OptionType::TargetLinkLayerAddress)) // Target Link-Layer Address
        {
            if (optionTotalLength < ICMPv6OptionLengthTargetLinkLayerAddress)
            {
                Debug::log("Invalid Target Link-Layer Address option length.");
                return false;
            }
            uint8_t targetMacAddressBytes[6];
            std::memcpy(targetMacAddressBytes, frameData + offset + 2, 6);

            Debug::log("ICMPv6 Target Link-Layer Address={}:{}:{}:{}:{}:{}", targetMacAddressBytes[0],
                       targetMacAddressBytes[1], targetMacAddressBytes[2], targetMacAddressBytes[3],
                       targetMacAddressBytes[4], targetMacAddressBytes[5]);
        }
        else if (optionType == static_cast<uint8_t>(ICMPv6OptionType::PrefixInformation)) // Prefix Information
        {
            if (optionTotalLength < ICMPv6OptionLengthPrefixInformation)
            {
                Debug::log("Invalid Prefix Information option length.");
                return false;
            }
            uint8_t prefixLength = frameData[offset + 2];
            uint8_t flags = frameData[offset + 3];
            uint32_t validLifetime = ntohl(*reinterpret_cast<const uint32_t *>(frameData + offset + 4));
            uint32_t preferredLifetime = ntohl(*reinterpret_cast<const uint32_t *>(frameData + offset + 8));
            // uint32_t reserved = ntohl(*reinterpret_cast<const uint32_t*>(frameData
            // + offset + 12));

            uint16_t prefixAddressParts[8];
            for (int i = 0; i < 8; ++i)
            {
                size_t addrOffset = offset + 16 + i * 2;
                prefixAddressParts[i] = ntohs(*reinterpret_cast<const uint16_t *>(frameData + addrOffset));
            }

            Debug::log("ICMPv6 Prefix Information: PrefixLength={}, Flags={}, "
                       "ValidLifetime={}, PreferredLifetime={}, "
                       "Prefix={}:{}:{}:{}:{}:{}:{}:{}",
                       prefixLength, flags, validLifetime, preferredLifetime, prefixAddressParts[0],
                       prefixAddressParts[1], prefixAddressParts[2], prefixAddressParts[3], prefixAddressParts[4],
                       prefixAddressParts[5], prefixAddressParts[6], prefixAddressParts[7]);
        }
        else // Unknown Option Type
        {
            Debug::log("ICMPv6 Unknown Option Type={}", optionType);
        }

        offset += optionTotalLength;
    }
    return true;
}

// ============================
// ICMPv6 Parsing
// ============================

static bool parse_icmpv6_neighbor_solicitation(const uint8_t *frameData, size_t frameLength, size_t offset, size_t end)
{
    if (end - offset < NeighborSolicitationMessageLength)
    {
        Debug::log("ICMPv6 Neighbor Solicitation message truncated.");
        return false;
    }

    uint16_t targetAddressParts[8];
    for (int i = 0; i < 8; ++i)
    {
        size_t addrOffset = offset + 8 + i * 2;
        targetAddressParts[i] = ntohs(*reinterpret_cast<const uint16_t *>(frameData + addrOffset));
    }

    Debug::log("ICMPv6 Neighbor Solicitation: Target Address={}:{}:{}:{}:{}:{}:{}:{}", targetAddressParts[0],
               targetAddressParts[1], targetAddressParts[2], targetAddressParts[3], targetAddressParts[4],
               targetAddressParts[5], targetAddressParts[6], targetAddressParts[7]);

    size_t optionsOffset = offset + NeighborSolicitationMessageLength;
    return parse_icmpv6_options(frameData, frameLength, optionsOffset, end);
}

static bool parse_icmpv6_neighbor_advertisement(const uint8_t *frameData, size_t frameLength, size_t offset, size_t end)
{
    if (end - offset < NeighborAdvertisementMessageLength)
    {
        Debug::log("ICMPv6 Neighbor Advertisement message truncated.");
        return false;
    }

    uint32_t flags = ntohl(*reinterpret_cast<const uint32_t *>(frameData + offset + 4));

    uint16_t targetAddressParts[8];
    for (int i = 0; i < 8; ++i)
    {
        size_t addrOffset = offset + 8 + i * 2;
        targetAddressParts[i] = ntohs(*reinterpret_cast<const uint16_t *>(frameData + addrOffset));
    }

    Debug::log("ICMPv6 Neighbor Advertisement: Target "
               "Address={}:{}:{}:{}:{}:{}:{}:{}, Flags={}",
               targetAddressParts[0], targetAddressParts[1], targetAddressParts[2], targetAddressParts[3],
               targetAddressParts[4], targetAddressParts[5], targetAddressParts[6], targetAddressParts[7], flags);

    size_t optionsOffset = offset + NeighborAdvertisementMessageLength;
    return parse_icmpv6_options(frameData, frameLength, optionsOffset, end);
}

static bool parse_icmpv6_router_solicitation(const uint8_t *frameData, size_t frameLength, size_t offset, size_t end)
{
    if (end - offset < RouterSolicitationMessageLength)
    {
        Debug::log("ICMPv6 Router Solicitation message truncated.");
        return false;
    }

    Debug::log("ICMPv6 Router Solicitation");

    size_t optionsOffset = offset + RouterSolicitationMessageLength;
    return parse_icmpv6_options(frameData, frameLength, optionsOffset, end);
}

static bool parse_icmpv6_router_advertisement(const uint8_t *frameData, size_t frameLength, size_t offset, size_t end)
{
    if (end - offset < RouterAdvertisementMessageLength)
    {
        Debug::log("ICMPv6 Router Advertisement message truncated.");
        return false;
    }

    uint8_t currentHopLimit = frameData[offset + 4];
    uint8_t flags = frameData[offset + 5];
    uint16_t routerLifetime = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset + 6));
    uint32_t reachableTime = ntohl(*reinterpret_cast<const uint32_t *>(frameData + offset + 8));
    uint32_t retransTimer = ntohl(*reinterpret_cast<const uint32_t *>(frameData + offset + 12));

    Debug::log("ICMPv6 Router Advertisement: Current Hop Limit={}, Flags={}, "
               "Router Lifetime={}, Reachable Time={}, Retrans Timer={}",
               currentHopLimit, flags, routerLifetime, reachableTime, retransTimer);

    size_t optionsOffset = offset + RouterAdvertisementMessageLength;
    return parse_icmpv6_options(frameData, frameLength, optionsOffset, end);
}

static bool parse_icmpv6(const uint8_t *frameData, size_t frameLength, size_t offset)
{
    if (offset + 8 > frameLength)
    {
        Debug::log("ICMPv6 header truncated.");
        return false;
    }

    uint8_t type = frameData[offset];
    uint8_t code = frameData[offset + 1];
    uint16_t checksum = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset + 2));
    // uint32_t reserved = ntohl(*reinterpret_cast<const uint32_t*>(frameData +
    // offset + 4));

    Debug::log("ICMPv6 Type={}, Code={}, Checksum={}", type, code, checksum);

    size_t messageOffset = offset + 8;
    size_t end = frameLength;

    if (type == static_cast<uint8_t>(ICMPv6Type::NeighborSolicitation)) // Neighbor Solicitation
    {
        return parse_icmpv6_neighbor_solicitation(frameData, frameLength, messageOffset, end);
    }
    else if (type == static_cast<uint8_t>(ICMPv6Type::NeighborAdvertisement)) // Neighbor Advertisement
    {
        return parse_icmpv6_neighbor_advertisement(frameData, frameLength, messageOffset, end);
    }
    else if (type == static_cast<uint8_t>(ICMPv6Type::RouterSolicitation)) // Router Solicitation
    {
        return parse_icmpv6_router_solicitation(frameData, frameLength, messageOffset, end);
    }
    else if (type == static_cast<uint8_t>(ICMPv6Type::RouterAdvertisement)) // Router Advertisement
    {
        return parse_icmpv6_router_advertisement(frameData, frameLength, messageOffset, end);
    }
    else // Unknown Type
    {
        Debug::log("ICMPv6 Unknown Type={}", type);
    }

    return true;
}

// ============================
// IPv6 and Neighbor Discovery
// ============================

static bool parse_ipv6_neighbor_discovery(const uint8_t *frameData, size_t frameLength, size_t offset)
{
    if (frameLength < offset + IPv6HeaderLength)
    {
        Debug::log("IPv6 header truncated.");
        return false;
    }

    uint16_t payloadLength = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset + 4));
    uint8_t nextHeader = frameData[offset + 6];
    uint8_t hopLimit = frameData[offset + 7];

    Debug::log("IPv6 PayloadLength={}, NextHeader={}, HopLimit={}", payloadLength, nextHeader, hopLimit);

    // ICMPv6 next header = 58
    if (nextHeader == ICMPv6NextHeader)
    {
        size_t icmpv6Offset = offset + IPv6HeaderLength;
        size_t icmpv6End = icmpv6Offset + payloadLength;

        if (icmpv6End > frameLength)
        {
            Debug::log("ICMPv6 payload exceeds frame length.");
            return false;
        }

        return parse_icmpv6(frameData, frameLength, icmpv6Offset);
    }
    else
    {
        Debug::log("Non-ICMPv6 NextHeader={}", nextHeader);
    }

    return true;
}

// ============================
// VLAN Parsing
// ============================

static bool parse_vlan_header(const uint8_t *frameData, size_t frameLength, size_t &offset, uint16_t &etherType)
{
    if (frameLength < offset + VlanHeaderLength + 2) // 4 for VLAN header + 2 for EtherType
    {
        Debug::log("VLAN header truncated.");
        return false;
    }

    uint16_t tagProtocolIdentifier = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset));
    uint16_t tagControlInformation = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset + 2));
    uint16_t vlanIdentifier = tagControlInformation & 0x0FFF;
    uint8_t priorityCodePoint = static_cast<uint8_t>((tagControlInformation >> 13) & 0x07);
    uint8_t dropEligibleIndicator = static_cast<uint8_t>((tagControlInformation >> 12) & 0x01);

    Debug::log("VLAN Tag: TPID={}, PCP={}, DEI={}, VLAN ID={}", tagProtocolIdentifier, priorityCodePoint,
               dropEligibleIndicator, vlanIdentifier);

    // Encapsulated EtherType
    etherType = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset + 4));
    offset += VlanHeaderLength + 2; // 4 bytes VLAN header + 2 bytes EtherType

    Debug::log("Encapsulated EtherType={}", etherType);

    return true;
}

// ============================
// ARP Payload Parsing
// ============================

static bool parse_arp_payload(const uint8_t *frameData, size_t frameLength, size_t offset)
{
    if (frameLength < offset + ARPPayloadLength)
    {
        Debug::log("ARP payload truncated.");
        return false;
    }

    uint16_t hardwareType = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset));
    uint16_t protocolType = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset + 2));
    uint8_t hardwareSize = frameData[offset + 4];
    uint8_t protocolSize = frameData[offset + 5];
    uint16_t opcode = ntohs(*reinterpret_cast<const uint16_t *>(frameData + offset + 6));

    uint8_t senderMacAddressBytes[6];
    std::memcpy(senderMacAddressBytes, frameData + offset + 8, 6);
    uint32_t senderIp =
        (static_cast<uint32_t>(frameData[offset + 14]) << 24) | (static_cast<uint32_t>(frameData[offset + 15]) << 16) |
        (static_cast<uint32_t>(frameData[offset + 16]) << 8) | static_cast<uint32_t>(frameData[offset + 17]);

    uint8_t targetMacAddressBytes[6];
    std::memcpy(targetMacAddressBytes, frameData + offset + 18, 6);
    uint32_t targetIp =
        (static_cast<uint32_t>(frameData[offset + 24]) << 24) | (static_cast<uint32_t>(frameData[offset + 25]) << 16) |
        (static_cast<uint32_t>(frameData[offset + 26]) << 8) | static_cast<uint32_t>(frameData[offset + 27]);

    if (hardwareSize != 6 || protocolSize != 4 || protocolType != static_cast<uint16_t>(ProtocolType::IPv4))
    {
        Debug::log("Invalid ARP payload parameters.");
        return false;
    }

    Debug::log("ARP HardwareType={}, ProtocolType={}, HardwareSize={}, "
               "ProtocolSize={}, Opcode={}, "
               "SenderMac={}:{}:{}:{}:{}:{}, SenderIp={}.{}.{}.{}, "
               "TargetMac={}:{}:{}:{}:{}:{}, TargetIp={}.{}.{}.{}",
               hardwareType, protocolType, hardwareSize, protocolSize, opcode, senderMacAddressBytes[0],
               senderMacAddressBytes[1], senderMacAddressBytes[2], senderMacAddressBytes[3], senderMacAddressBytes[4],
               senderMacAddressBytes[5], (senderIp >> 24) & 0xFF, (senderIp >> 16) & 0xFF, (senderIp >> 8) & 0xFF,
               senderIp & 0xFF, targetMacAddressBytes[0], targetMacAddressBytes[1], targetMacAddressBytes[2],
               targetMacAddressBytes[3], targetMacAddressBytes[4], targetMacAddressBytes[5], (targetIp >> 24) & 0xFF,
               (targetIp >> 16) & 0xFF, (targetIp >> 8) & 0xFF, targetIp & 0xFF);

    return true;
}

// ============================
// Ethernet Frame Parsing
// ============================

static bool parse_ethernet_header(const uint8_t *frameData, size_t frameLength)
{
    size_t offset = 0;
    uint8_t destinationMacAddressBytes[6];
    uint8_t sourceMacAddressBytes[6];
    uint16_t etherType;

    if (frameLength < EthernetHeaderLength)
    {
        Debug::log("Ethernet frame too short.");
        return false;
    }

    std::memcpy(destinationMacAddressBytes, frameData, 6);
    std::memcpy(sourceMacAddressBytes, frameData + 6, 6);

    // Manually assemble EtherType using ntohs
    etherType = ntohs(*reinterpret_cast<const uint16_t *>(frameData + 12));

    offset += EthernetHeaderLength;

    Debug::log("Ethernet DestinationMac={}:{}:{}:{}:{}:{}, "
               "SourceMac={}:{}:{}:{}:{}:{}, EtherType={}",
               destinationMacAddressBytes[0], destinationMacAddressBytes[1], destinationMacAddressBytes[2],
               destinationMacAddressBytes[3], destinationMacAddressBytes[4], destinationMacAddressBytes[5],
               sourceMacAddressBytes[0], sourceMacAddressBytes[1], sourceMacAddressBytes[2], sourceMacAddressBytes[3],
               sourceMacAddressBytes[4], sourceMacAddressBytes[5], etherType);

    // Handle VLAN tags if present
    size_t vlanCount = 0;

    while (
        (etherType == static_cast<uint16_t>(EtherType::VLAN) || etherType == static_cast<uint16_t>(EtherType::QinQ)) &&
        vlanCount < MaxVlanTags)
    {
        if (!parse_vlan_header(frameData, frameLength, offset, etherType))
        {
            return false;
        }
        vlanCount++;
    }

    if (vlanCount == MaxVlanTags &&
        (etherType == static_cast<uint16_t>(EtherType::VLAN) || etherType == static_cast<uint16_t>(EtherType::QinQ)))
    {
        Debug::log("Exceeded maximum VLAN tags.");
        return false;
    }

    // Determine payload based on EtherType
    if (etherType == static_cast<uint16_t>(EtherType::ARP))
    {
        // ARP
        return parse_arp_payload(frameData, frameLength, offset);
    }
    else if (etherType == static_cast<uint16_t>(EtherType::IPv6))
    {
        // IPv6
        return parse_ipv6_neighbor_discovery(frameData, frameLength, offset);
    }
    else
    {
        Debug::log("Unknown EtherType={}", etherType);
        return false;
    }
}

// ============================
// Main Compartment Function
// ============================

[[noreturn]] void __cheri_compartment("entry_point") init()
{
    Debug::log("Setup ethernet device.");
    EthernetDevice ethernet;

    Debug::log("Set default MAC address.");
    ethernet.mac_address_set();

    Debug::log("Start loop.");
    while (true)
    {
        uint32_t lastInterrupt = ethernet.receive_interrupt_value();

        Debug::log("Receive interrupt value is {}.", lastInterrupt);

        while (auto maybeFrame = ethernet.receive_frame())
        {
            auto &frame = *maybeFrame;

            Debug::log("Frame of {} bytes received. Parse frame.", static_cast<uint32_t>(frame.length));

            // Parse the Ethernet frame
            if (!parse_ethernet_header(frame.buffer, frame.length))
            {
                Debug::log("Failed to parse Ethernet frame.");
            }
        }

        Timeout timeoutInstance{UnlimitedTimeout};
        ethernet.receive_interrupt_complete(&timeoutInstance, lastInterrupt);
    }
}
