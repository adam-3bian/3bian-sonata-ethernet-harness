#include <compartment.h>
#include <fail-simulator-on-error.h>

#include <debug.hh>
#include <locks.hh>
#include <timeout.hh>

#include "ethernet.hh"

using Debug = ConditionalDebug<true, "Ethernet harness">;

// ============================
// Network to Host Conversions
// ============================

uint32_t constexpr ntohl(uint32_t value)
{
#ifdef __LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value; // do nothing.
#endif
}

uint16_t constexpr ntohs(uint16_t value)
{
#ifdef __LITTLE_ENDIAN__
    return __builtin_bswap16(value);
#else
    return value; // do nothing.
#endif
}

// ============================
// Ethernet
// ============================

void parse_ethernet_header(uint8_t *frame, uint16_t frameLength);
void parse_vlan_header(uint8_t *remaining, uint16_t remainingLength);
void parse_double_vlan_header(uint8_t *remaining, uint16_t remainingLength);
void parse_arp_header(uint8_t *remaining, uint16_t remainingLength);
void parse_ipv4_arp_header(uint8_t *remaining, uint16_t remainingLength);
void parse_ipv6_arp_header(uint8_t *remaining, uint16_t remainingLength);
void parse_ipv4_header(uint8_t *remaining, uint16_t remainingLength);
void parse_ipv6_header(uint8_t *remaining, uint16_t remainingLength);
void parse_udp_header(uint8_t *remaining, uint16_t remainingLength);
void parse_dhcp6_header(uint8_t *remaining, uint16_t remainingLength);
void parse_icmpv6_header(uint8_t *remaining, uint16_t remainingLength);
void parse_icmpv6_router_advertisement(uint8_t *remaining, uint16_t remainingLength);

void parse_ethernet_header(uint8_t *frame, uint16_t frameLength)
{
    if (frameLength < 14)
    {
        Debug::log("Frame too short for Ethernet header: {}", frameLength);
        return; // Not enough length for Ethernet header
    }

    uint8_t destinationHardwareAddress[6];
    uint8_t sourceHardwareAddress[6];
    uint16_t etherType;

    memcpy(destinationHardwareAddress, frame, 6);
    memcpy(sourceHardwareAddress, frame + 6, 6);
    memcpy(&etherType, frame + 12, 2);

    etherType = ntohs(etherType);

    Debug::log("EtherType: {}", etherType);
    Debug::log("Destination Hardware Address: {}:{}:{}:{}:{}:{}",
               destinationHardwareAddress[0], destinationHardwareAddress[1], destinationHardwareAddress[2],
               destinationHardwareAddress[3], destinationHardwareAddress[4], destinationHardwareAddress[5]);
    Debug::log("Source Hardware Address: {}:{}:{}:{}:{}:{}",
               sourceHardwareAddress[0], sourceHardwareAddress[1], sourceHardwareAddress[2],
               sourceHardwareAddress[3], sourceHardwareAddress[4], sourceHardwareAddress[5]);

    if (etherType == 0x0800) // IPv4
    {
        Debug::log("Parsing IPv4 header");
        parse_ipv4_header(frame + 14, frameLength - 14);
    }
    else if (etherType == 0x0806) // ARP
    {
        Debug::log("Parsing ARP header");
        parse_arp_header(frame + 14, frameLength - 14);
    }
    else if (etherType == 0x8100) // VLAN
    {
        Debug::log("Parsing VLAN header");
        parse_vlan_header(frame + 14, frameLength - 14);
    }
    else if (etherType == 0x86DD) // IPv6
    {
        Debug::log("Parsing IPv6 header");
        parse_ipv6_header(frame + 14, frameLength - 14);
    }
    else if (etherType == 0x88A8) // Double VLAN (Q-in-Q)
    {
        Debug::log("Parsing Double VLAN header (Q-in-Q)");
        parse_double_vlan_header(frame + 14, frameLength - 14);
    }
    else
    {
        Debug::log("Unknown EtherType: {}", etherType);
    }
}

// ============================
// Ethernet/VLAN
// ============================

void parse_vlan_header(uint8_t *remaining, uint16_t remainingLength)
{
    if (remainingLength < 6)
    {
        Debug::log("Frame too short for VLAN header: {}", remainingLength);
        return; // Not enough length for VLAN header
    }

    uint16_t tpid;
    uint16_t tci;
    uint16_t nextEtherType;

    memcpy(&tpid, remaining, 2);
    memcpy(&tci, remaining + 2, 2);
    memcpy(&nextEtherType, remaining + 4, 2);

    tpid = ntohs(tpid);
    tci = ntohs(tci);
    nextEtherType = ntohs(nextEtherType);

    uint8_t priority = (tci >> 13) & 0x07; // Extract Priority (3 bits)
    uint8_t cfi = (tci >> 12) & 0x01;      // Extract CFI/DEI (1 bit)
    uint16_t vlanId = tci & 0x0FFF;        // Extract VLAN ID (12 bits)

    Debug::log("TPID: {}", tpid);
    Debug::log("Priority: {}", priority);
    Debug::log("CFI/DEI: {}", cfi);
    Debug::log("VLAN ID: {}", vlanId);
    Debug::log("Next EtherType: {}", nextEtherType);

    if (nextEtherType == 0x8100 || nextEtherType == 0x88A8) // Double VLAN (Q-in-Q)
    {
        Debug::log("Parsing double VLAN header (Q-in-Q)");
        parse_double_vlan_header(remaining + 6, remainingLength - 6);
    }
    else if (nextEtherType == 0x0800) // IPv4
    {
        Debug::log("Parsing IPv4 header");
        parse_ipv4_header(remaining + 6, remainingLength - 6);
    }
    else if (nextEtherType == 0x0806) // ARP
    {
        Debug::log("Parsing ARP header");
        parse_arp_header(remaining + 6, remainingLength - 6);
    }
    else if (nextEtherType == 0x86DD) // IPv6
    {
        Debug::log("Parsing IPv6 header");
        parse_ipv6_header(remaining + 6, remainingLength - 6);
    }
    else
    {
        Debug::log("Unknown EtherType after VLAN: {}", nextEtherType);
    }
}

void parse_double_vlan_header(uint8_t *remaining, uint16_t remainingLength)
{
    if (remainingLength < 8)
    {
        Debug::log("Frame too short for Double VLAN header: {}", remainingLength);
        return; // Not enough length for Double VLAN header
    }

    uint16_t outerTpid;
    uint16_t outerTci;
    uint16_t innerTpid;
    uint16_t innerTci;
    uint16_t nextEtherType;

    memcpy(&outerTpid, remaining, 2);
    memcpy(&outerTci, remaining + 2, 2);
    memcpy(&innerTpid, remaining + 4, 2);
    memcpy(&innerTci, remaining + 6, 2);
    memcpy(&nextEtherType, remaining + 8, 2);

    outerTpid = ntohs(outerTpid);
    outerTci = ntohs(outerTci);
    innerTpid = ntohs(innerTpid);
    innerTci = ntohs(innerTci);
    nextEtherType = ntohs(nextEtherType);

    uint8_t outerPriority = (outerTci >> 13) & 0x07;  // Extract Outer Priority (3 bits)
    uint8_t outerCfi = (outerTci >> 12) & 0x01;       // Extract Outer CFI/DEI (1 bit)
    uint16_t outerVlanId = outerTci & 0x0FFF;         // Extract Outer VLAN ID (12 bits)
    uint8_t innerPriority = (innerTci >> 13) & 0x07;  // Extract Inner Priority (3 bits)
    uint8_t innerCfi = (innerTci >> 12) & 0x01;       // Extract Inner CFI/DEI (1 bit)
    uint16_t innerVlanId = innerTci & 0x0FFF;         // Extract Inner VLAN ID (12 bits)

    Debug::log("Outer TPID: {}", outerTpid);
    Debug::log("Outer Priority: {}", outerPriority);
    Debug::log("Outer CFI/DEI: {}", outerCfi);
    Debug::log("Outer VLAN ID: {}", outerVlanId);
    Debug::log("Inner TPID: {}", innerTpid);
    Debug::log("Inner Priority: {}", innerPriority);
    Debug::log("Inner CFI/DEI: {}", innerCfi);
    Debug::log("Inner VLAN ID: {}", innerVlanId);

    if (nextEtherType == 0x0800) // IPv4
    {
        Debug::log("Parsing IPv4 header");
        parse_ipv4_header(remaining + 10, remainingLength - 10);
    }
    else if (nextEtherType == 0x0806) // ARP
    {
        Debug::log("Parsing ARP header");
        parse_arp_header(remaining + 10, remainingLength - 10);
    }
    else if (nextEtherType == 0x86DD) // IPv6
    {
        Debug::log("Parsing IPv6 header");
        parse_ipv6_header(remaining + 10, remainingLength - 10);
    }
    else
    {
        Debug::log("Unknown EtherType after Double VLAN: {}", nextEtherType);
    }
}

// ============================
// Ethernet/Arp
// ============================

void parse_arp_header(uint8_t *remaining, uint16_t remainingLength)
{    
    if (remainingLength < 28) // Minimum ARP header size
    {
        Debug::log("Frame too short for ARP header: {}", remainingLength);
        return; // Not enough length for ARP header
    }

    uint16_t hardwareType;
    uint16_t protocolType;
    uint16_t operation;

    memcpy(&hardwareType, remaining, 2);
    memcpy(&protocolType, remaining + 2, 2);
    memcpy(&operation, remaining + 6, 2);

    hardwareType = ntohs(hardwareType);
    protocolType = ntohs(protocolType);
    operation = ntohs(operation);

    Debug::log("Hardware Type: {}", hardwareType);
    Debug::log("Protocol Type: {}", protocolType);
    Debug::log("Operation: {}", operation);

    if (protocolType == 0x0800) // IPv4
    {
        parse_ipv4_arp_header(remaining, remainingLength);
    }
    else if (protocolType == 0x86DD) // IPv6
    {
        parse_ipv6_arp_header(remaining, remainingLength);
    }
    else
    {
        Debug::log("Unknown or unsupported protocol type: {}", protocolType);
    }
}

void parse_ipv4_arp_header(uint8_t *remaining, uint16_t remainingLength)
{
    const uint8_t hardwareAddressLength = 6;
    const uint8_t protocolAddressLength = 4;

    if (remainingLength < 8 + (2 * hardwareAddressLength) + (2 * protocolAddressLength))
    {
        Debug::log("Frame too short for IPv4 ARP data: {}", remainingLength);
        return;
    }

    uint8_t senderHardwareAddress[6];
    uint8_t targetHardwareAddress[6];
    uint8_t senderIpv4Address[4];
    uint8_t targetIpv4Address[4];

    memcpy(senderHardwareAddress, remaining + 8, hardwareAddressLength);
    memcpy(senderIpv4Address, remaining + 8 + hardwareAddressLength, protocolAddressLength);
    memcpy(targetHardwareAddress, remaining + 8 + hardwareAddressLength + protocolAddressLength, hardwareAddressLength);
    memcpy(targetIpv4Address, remaining + 8 + (2 * hardwareAddressLength) + protocolAddressLength, protocolAddressLength);

    Debug::log("Sender IPv4 Address: {}.{}.{}.{}",
               senderIpv4Address[0], senderIpv4Address[1],
               senderIpv4Address[2], senderIpv4Address[3]);
    Debug::log("Target IPv4 Address: {}.{}.{}.{}",
               targetIpv4Address[0], targetIpv4Address[1],
               targetIpv4Address[2], targetIpv4Address[3]);
    Debug::log("Sender Hardware Address: {}:{}:{}:{}:{}:{}",
               senderHardwareAddress[0], senderHardwareAddress[1], senderHardwareAddress[2],
               senderHardwareAddress[3], senderHardwareAddress[4], senderHardwareAddress[5]);
    Debug::log("Target Hardware Address: {}:{}:{}:{}:{}:{}",
               targetHardwareAddress[0], targetHardwareAddress[1], targetHardwareAddress[2],
               targetHardwareAddress[3], targetHardwareAddress[4], targetHardwareAddress[5]);
}

void parse_ipv6_arp_header(uint8_t *remaining, uint16_t remainingLength)
{
    const uint8_t hardwareAddressLength = 6;
    const uint8_t protocolAddressLength = 16;

    if (remainingLength < 8 + (2 * hardwareAddressLength) + (2 * protocolAddressLength))
    {
        Debug::log("Frame too short for IPv6 ARP data: {}", remainingLength);
        return;
    }

    uint8_t senderHardwareAddress[6];
    uint8_t targetHardwareAddress[6];
    uint8_t senderIpv6Address[16];
    uint8_t targetIpv6Address[16];

    memcpy(senderHardwareAddress, remaining + 8, hardwareAddressLength);
    memcpy(senderIpv6Address, remaining + 8 + hardwareAddressLength, protocolAddressLength);
    memcpy(targetHardwareAddress, remaining + 8 + hardwareAddressLength + protocolAddressLength, hardwareAddressLength);
    memcpy(targetIpv6Address, remaining + 8 + (2 * hardwareAddressLength) + protocolAddressLength, protocolAddressLength);

    Debug::log("Sender IPv6 Address: "
               "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
               senderIpv6Address[0], senderIpv6Address[1], senderIpv6Address[2], senderIpv6Address[3],
               senderIpv6Address[4], senderIpv6Address[5], senderIpv6Address[6], senderIpv6Address[7],
               senderIpv6Address[8], senderIpv6Address[9], senderIpv6Address[10], senderIpv6Address[11],
               senderIpv6Address[12], senderIpv6Address[13], senderIpv6Address[14], senderIpv6Address[15]);

    Debug::log("Target IPv6 Address: "
               "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
               targetIpv6Address[0], targetIpv6Address[1], targetIpv6Address[2], targetIpv6Address[3],
               targetIpv6Address[4], targetIpv6Address[5], targetIpv6Address[6], targetIpv6Address[7],
               targetIpv6Address[8], targetIpv6Address[9], targetIpv6Address[10], targetIpv6Address[11],
               targetIpv6Address[12], targetIpv6Address[13], targetIpv6Address[14], targetIpv6Address[15]);

    Debug::log("Sender Hardware Address: {}:{}:{}:{}:{}:{}",
               senderHardwareAddress[0], senderHardwareAddress[1], senderHardwareAddress[2],
               senderHardwareAddress[3], senderHardwareAddress[4], senderHardwareAddress[5]);
    Debug::log("Target Hardware Address: {}:{}:{}:{}:{}:{}",
               targetHardwareAddress[0], targetHardwareAddress[1], targetHardwareAddress[2],
               targetHardwareAddress[3], targetHardwareAddress[4], targetHardwareAddress[5]);
}

// ============================
// Ethernet/IPv4
// ============================

void parse_ipv4_header(uint8_t *remaining, uint16_t remainingLength)
{
    if (remainingLength < 20) // Minimum IPv4 header size
    {
        Debug::log("Frame too short for IPv4 header: {}", remainingLength);
        return;
    }

    uint8_t versionAndIhl;
    uint8_t dscpAndEcn;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsAndFragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint8_t sourceIp[4];
    uint8_t destinationIp[4];

    memcpy(&versionAndIhl, remaining, 1);
    memcpy(&dscpAndEcn, remaining + 1, 1);
    memcpy(&totalLength, remaining + 2, 2);
    memcpy(&identification, remaining + 4, 2);
    memcpy(&flagsAndFragmentOffset, remaining + 6, 2);
    memcpy(&ttl, remaining + 8, 1);
    memcpy(&protocol, remaining + 9, 1);
    memcpy(&headerChecksum, remaining + 10, 2);
    memcpy(sourceIp, remaining + 12, 4);
    memcpy(destinationIp, remaining + 16, 4);

    totalLength = ntohs(totalLength);
    identification = ntohs(identification);
    flagsAndFragmentOffset = ntohs(flagsAndFragmentOffset);
    headerChecksum = ntohs(headerChecksum);

    uint16_t headerLength = (versionAndIhl & 0x0F) * 4;

    Debug::log("IPv4 Header Length: {}", headerLength);
    Debug::log("IPv4 Total Length: {}", totalLength);
    Debug::log("Source IPv4 Address: {}.{}.{}.{}", sourceIp[0], sourceIp[1], sourceIp[2], sourceIp[3]);
    Debug::log("Destination IPv4 Address: {}.{}.{}.{}", destinationIp[0], destinationIp[1], destinationIp[2], destinationIp[3]);
    Debug::log("Protocol: {}", protocol);

    if (protocol == 0x01) // ICMP
    {
        Debug::log("ICMP Protocol detected.");
        //parse_icmp_header(remaining + headerLength, remainingLength - headerLength);
    }
    else if (protocol == 0x02) // IGMP
    {
        Debug::log("IGMP Protocol detected.");
        //parse_igmp_header(remaining + headerLength, remainingLength - headerLength);
    }
    else if (protocol == 0x06) // TCP
    {
        Debug::log("TCP Protocol detected.");
        //parse_tcp_header(remaining + headerLength, remainingLength - headerLength);
    }
    else if (protocol == 0x11) // UDP
    {
        Debug::log("UDP Protocol detected.");
        parse_udp_header(remaining + headerLength, remainingLength - headerLength);
    }
    else
    {
        Debug::log("Unknown protocol in IPv4 header: {}", protocol);
    }
}

// ============================
// Ethernet/IPv6
// ============================

void parse_ipv6_header(uint8_t *remaining, uint16_t remainingLength)
{
    if (remainingLength < 40) // Fixed IPv6 header size
    {
        Debug::log("Frame too short for IPv6 header: {}", remainingLength);
        return;
    }

    uint8_t versionAndTrafficClass;
    uint32_t flowLabel;
    uint16_t payloadLength;
    uint8_t nextHeader;
    uint8_t hopLimit;
    uint8_t sourceIp[16];
    uint8_t destinationIp[16];

    memcpy(&versionAndTrafficClass, remaining, 1);
    memcpy(&flowLabel, remaining + 1, 3);
    memcpy(&payloadLength, remaining + 4, 2);
    memcpy(&nextHeader, remaining + 6, 1);
    memcpy(&hopLimit, remaining + 7, 1);
    memcpy(sourceIp, remaining + 8, 16);
    memcpy(destinationIp, remaining + 24, 16);

    payloadLength = ntohs(payloadLength);

    Debug::log("IPv6 Payload Length: {}", payloadLength);
    Debug::log("Source IPv6 Address: {}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
               sourceIp[0], sourceIp[1], sourceIp[2], sourceIp[3],
               sourceIp[4], sourceIp[5], sourceIp[6], sourceIp[7],
               sourceIp[8], sourceIp[9], sourceIp[10], sourceIp[11],
               sourceIp[12], sourceIp[13], sourceIp[14], sourceIp[15]);
    Debug::log("Destination IPv6 Address: {}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
               destinationIp[0], destinationIp[1], destinationIp[2], destinationIp[3],
               destinationIp[4], destinationIp[5], destinationIp[6], destinationIp[7],
               destinationIp[8], destinationIp[9], destinationIp[10], destinationIp[11],
               destinationIp[12], destinationIp[13], destinationIp[14], destinationIp[15]);
    Debug::log("Next Header: {}", nextHeader);

    if (nextHeader == 0x00) // Hop-by-Hop
    {
        Debug::log("Hop-by-Hop Protocol detected.");
    }
    else if (nextHeader == 0x06) // TCP
    {
        Debug::log("TCP Protocol detected.");
        //parse_tcp_header(remaining + 40, remainingLength - 40);
    }
    else if (nextHeader == 0x11) // UDP
    {
        Debug::log("UDP Protocol detected.");
        parse_udp_header(remaining + 40, remainingLength - 40);
    }
    else if (nextHeader == 0x3A) // ICMPv6
    {
        Debug::log("ICMPv6 Protocol detected.");
        parse_icmpv6_header(remaining + 40, remainingLength - 40);
    }
    else
    {
        Debug::log("** Unknown next header in IPv6: {}", nextHeader);
    }
}

// ============================
// Ethernet/IPv?/UDP
// ============================

void parse_udp_header(uint8_t *remaining, uint16_t remainingLength)
{
    if (remainingLength < 8) // Minimum UDP header size
    {
        Debug::log("Frame too short for UDP header: {}", remainingLength);
        return;
    }

    uint16_t sourcePort;
    uint16_t destinationPort;
    uint16_t length;
    uint16_t checksum;

    memcpy(&sourcePort, remaining, 2);
    memcpy(&destinationPort, remaining + 2, 2);
    memcpy(&length, remaining + 4, 2);
    memcpy(&checksum, remaining + 6, 2);

    sourcePort = ntohs(sourcePort);
    destinationPort = ntohs(destinationPort);
    length = ntohs(length);
    checksum = ntohs(checksum);

    Debug::log("UDP Source Port: {}", sourcePort);
    Debug::log("UDP Destination Port: {}", destinationPort);
    Debug::log("UDP Length: {}", length);
    Debug::log("UDP Checksum: {}", checksum);

    if (destinationPort == 546 || sourcePort == 547) // DHCPv6
    {
        Debug::log("Parsing DHCPv6 payload");
        parse_dhcp6_header(remaining + 8, length - 8);
    }
    else
    {
        Debug::log("Unknown UDP payload, Source Port: {}, Destination Port: {}", sourcePort, destinationPort);
    }
}

// ============================
// Ethernet/IPv?/UDP/DHCP6
// ============================

void parse_dhcp6_header(uint8_t *remaining, uint16_t remainingLength)
{
    if (remainingLength < 4) // Minimum DHCPv6 header size
    {
        Debug::log("Frame too short for DHCPv6 header: {}", remainingLength);
        return;
    }

    uint8_t messageType;
    uint32_t transactionId;

    memcpy(&messageType, remaining, 1);
    memcpy(&transactionId, remaining + 1, 3);

    Debug::log("DHCPv6 Message Type: {}", messageType);
    Debug::log("DHCPv6 Transaction ID: {}", transactionId);
}

// ============================
// Ethernet/IPv6/ICMPv6
// ============================

void parse_icmpv6_header(uint8_t *remaining, uint16_t remainingLength)
{
    if (remainingLength < 4)
    {
        Debug::log("Frame too short for ICMPv6 header: {}", remainingLength);
        return;
    }

    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    memcpy(&type, remaining, 1);
    memcpy(&code, remaining + 1, 1);
    memcpy(&checksum, remaining + 2, 2);

    checksum = ntohs(checksum);

    Debug::log("ICMPv6 Type: {}", type);
    Debug::log("ICMPv6 Code: {}", code);
    Debug::log("ICMPv6 Checksum: {}", checksum);

    if (type == 133) // Router Solicitation
    {
        Debug::log("Router Solicitation message received.");
        //parse_router_solicitation(remaining + 4, remainingLength - 4);
    }
    else if (type == 134) // Router Advertisement
    {
        Debug::log("Router Advertisement message received.");
        parse_icmpv6_router_advertisement(remaining + 4, remainingLength - 4);
    }
    else if (type == 135)
    {
        Debug::log("Neighbor Solicitation message received.");
    }
    else
    {
        Debug::log("Unhandled ICMPv6 type: {}", type);
    }
}

void parse_icmpv6_router_advertisement(uint8_t *remaining, uint16_t remainingLength)
{
    if (remainingLength < 16)
    {
        Debug::log("Frame too short for Router Advertisement: {}", remainingLength);
        return;
    }

    uint8_t curHopLimit;
    uint8_t flags;
    uint16_t routerLifetime;
    uint32_t reachableTime;
    uint32_t retransTimer;

    memcpy(&curHopLimit, remaining, 1);
    memcpy(&flags, remaining + 1, 1);
    memcpy(&routerLifetime, remaining + 2, 2);
    memcpy(&reachableTime, remaining + 4, 4);
    memcpy(&retransTimer, remaining + 8, 4);

    routerLifetime = ntohs(routerLifetime);
    reachableTime = ntohl(reachableTime);
    retransTimer = ntohl(retransTimer);

    Debug::log("Current Hop Limit: {}", curHopLimit);
    Debug::log("Flags: 0x{:02x}", flags);
    Debug::log("Router Lifetime: {} seconds", routerLifetime);
    Debug::log("Reachable Time: {} ms", reachableTime);
    Debug::log("Retransmission Timer: {} ms", retransTimer);

    //parse_ra_options(remaining + 16, remainingLength - 16);
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
            parse_ethernet_header(frame.buffer, frame.length);            
        }

        Timeout timeoutInstance{UnlimitedTimeout};
        ethernet.receive_interrupt_complete(&timeoutInstance, lastInterrupt);
    }
}
