#include <Airport/SequoiaNativeJoin.h>
#include <Airport/SequoiaExtendedBss.h>
#include <cassert>
#include <cstdio>
#include <vector>

using IOReturn = int;
enum { kIOReturnSuccess, kIOReturnBadArgument, kIOReturnNotReady, kIOReturnUnsupported };
enum { IEEE80211_S_RUN = 4, IEEE80211_NODE_HT = 1, IEEE80211_NODE_VHT = 2,
       IEEE80211_NODE_HE = 4, IEEE80211_CHAN_WIDTH_160 = 160, IEEE80211_CHAN_WIDTH_80P80 = 8080 };
#define le16toh(value) (value) // This test and the audited ABI are x86_64.
enum { IWM_MIN_DBM = -100 };
#define OSDynamicCast(type, pointer) dynamic_cast<type *>(pointer)
#define IEEE80211_CHAN_ANYC reinterpret_cast<::Channel *>(-1)
#define IEEE80211_IS_CHAN_2GHZ(channel) ((channel)->band == 2)
#define IEEE80211_IS_CHAN_5GHZ(channel) ((channel)->band == 5)
struct Channel { unsigned number = 1, band = 2; };
struct HeMaps { uint16_t rx_mcs_80 = 0xfffa, tx_mcs_80 = 0xfffa,
    rx_mcs_160 = 0xfffe, tx_mcs_160 = 0xfffe, rx_mcs_80p80 = 0xffff, tx_mcs_80p80 = 0xffff; };
struct ieee80211_node {
    Channel channel, *ni_chan = &channel;
    uint8_t ni_essid[32] = {'a',0,'b'}, ni_bssid[6] = {2,0,0,0,0,0};
    uint8_t ni_esslen = 3;
    uint8_t *ni_rsnie_tlv = nullptr;
    unsigned ni_rsnie_tlv_len = 0;
    int ni_rssi = 45;
    uint16_t ni_capinfo = 1, ni_intval = 100;
    struct { uint8_t rs_nrates = 3, rs_rates[16] = {0x8c, 24, 108}; } ni_rates;
    uint8_t ni_rxmcs[10] = {0xff, 0xff};
    unsigned ni_flags = IEEE80211_NODE_HT | IEEE80211_NODE_VHT, ni_chw = 80;
    struct { uint16_t rx_mcs_map = 0xfffa; } ni_vht_mcsinfo;
    HeMaps ni_he_mcs_nss_supp;
};
struct Com { ieee80211_node *ic_bss = nullptr; int ic_state = IEEE80211_S_RUN;
    uint8_t ic_sup_mcs[10] = {0xff}; uint16_t ic_vht_tx_mcs_map = 0xfffd;
    HeMaps ic_he_mcs_nss_supp; };
static unsigned ieee80211_chan2ieee(Com *, Channel *channel) { return channel->number; }
struct Base { virtual ~Base() = default; };
struct ItlIwm : Base {
    Com ic;
    struct { int sc_generation = 1; } com;
    int nativeStateError = 0;
    ItlJoin::Progress nativeJoinProgress;
    Com *get80211Controller() { return &ic; }
    ItlIwm *getNativeHal() { return this; }
    Com *nativeController() { return &ic; }
    int nativeStateErrorCode() const { return nativeStateError; }
    uint64_t nativeGeneration() const { return com.sc_generation; }
    const ItlJoin::Progress &nativeJoinProgressState() const { return nativeJoinProgress; }
};
struct Owner {
    struct Loop { bool gated = true; bool inGate() { return gated; } } loop;
    bool available = true;
    SequoiaWCL::NativeJoin nativeJoin;
    uint32_t configurationSetters = 0;
    uint32_t lastConfigurationSetter = UINT32_MAX;
    Loop *getWorkQueue() { return &loop; }
    bool nativeRadioAvailable() { return available && loop.gated; }
    bool nativeHardwareQueryAvailable() { return available && loop.gated; }
    void publishNativeJoinDiagnostics() {}
    void recordConfigurationSetter(uint32_t selector)
    {
        ++configurationSetters;
        lastConfigurationSetter = selector;
    }
};
struct AirportItlwmSkywalkInterface {
    Owner *instance = nullptr;
    ItlIwm *fHalService = nullptr;
    IOReturn getSequoiaBSSInfo(void *);
    IOReturn getSequoiaExtendedBSSInfo(void *);
    IOReturn setSequoiaFastLane(void *);
    IOReturn setSequoiaArpMode(void *);
    IOReturn getSequoiaLowLatencyInfo(void *);
    IOReturn getSequoiaHardwareAddress(void *);
    uint8_t nativePermanentAddress[6] = {0x88,1,2,3,4,5};
    size_t encodeWCLScanResult(const ieee80211_node *, void *, size_t);
};
#include "sequoia_bss_controller_methods.inc"

int main()
{
    using namespace SequoiaWCL;
    unsigned traces = 0;
    for (unsigned fault = 0; fault < 6; ++fault) {
        for (unsigned alignment = 0; alignment < 8; ++alignment) {
            Owner owner; ItlIwm hal;
            AirportItlwmSkywalkInterface interface{&owner, &hal};
            if (fault == 1) interface.instance = nullptr;
            if (fault == 2) owner.available = false;
            if (fault == 3) owner.loop.gated = false;
            if (fault == 4) memset(interface.nativePermanentAddress, 0, 6);
            if (fault == 5) interface.nativePermanentAddress[0] |= 1;
            uint8_t bytes[24]; memset(bytes, 0xa5, sizeof(bytes));
            const uint8_t expected[12] = {1,0,0,0,0x88,1,2,3,4,5,0,0};
            assert(interface.getSequoiaHardwareAddress(nullptr) == kIOReturnBadArgument);
            assert(interface.getSequoiaHardwareAddress(bytes + alignment) ==
                   (fault ? kIOReturnNotReady : kIOReturnSuccess));
            for (unsigned i = 0; i < sizeof(bytes); ++i)
                assert(bytes[i] == ((!fault && i >= alignment && i < alignment + 12)
                       ? expected[i - alignment] : 0xa5));
            ++traces;
        }
    }
    // Join's mandatory 4-byte status query must not overwrite its adjacent
    // stack fields, including with unaligned output or unavailable hardware.
    for (unsigned fault = 0; fault < 4; ++fault) {
        for (unsigned alignment = 0; alignment < 8; ++alignment) {
            Owner owner; ItlIwm hal;
            AirportItlwmSkywalkInterface interface{&owner, &hal};
            if (fault == 1) interface.instance = nullptr;
            if (fault == 2) owner.available = false;
            if (fault == 3) owner.loop.gated = false;
            uint8_t bytes[16]; memset(bytes, 0xa5, sizeof(bytes));
            assert(interface.getSequoiaLowLatencyInfo(nullptr) == kIOReturnBadArgument);
            assert(interface.getSequoiaLowLatencyInfo(bytes + alignment) ==
                   (fault ? kIOReturnNotReady : kIOReturnSuccess));
            for (unsigned i = 0; i < sizeof(bytes); ++i)
                assert(bytes[i] == ((!fault && i >= alignment && i < alignment + 4) ? 0 : 0xa5));
            ++traces;
        }
    }
    for (unsigned fault = 0; fault < 24; ++fault) {
        for (unsigned alignment = 0; alignment < 8; ++alignment) {
            Owner owner; ItlIwm hal; ieee80211_node node;
            AirportItlwmSkywalkInterface interface{&owner, &hal};
            hal.ic.ic_bss = &node;
            uint8_t ies[] = {0,3,'a',0,'b',1,1,0x82,3,1,1};
            node.ni_rsnie_tlv = ies; node.ni_rsnie_tlv_len = sizeof(ies);
            auto &join = owner.nativeJoin;
            join.busy = join.started = join.associationReady = true;
            join.generation = 1;
            assert(hal.nativeJoinProgress.begin(node.ni_bssid, 1));
            switch (fault) {
                case 1: interface.instance = nullptr; break;
                case 2: owner.loop.gated = false; break;
                case 3: owner.available = false; break;
                case 4: interface.fHalService = nullptr; break;
                case 5: join.busy = false; break;
                case 6: join.started = false; break;
                case 7: join.cancel = true; break;
                case 8: join.error = 5; break;
                case 9: join.drained = true; break;
                case 10: join.associationReady = false; break;
                case 11: join.association.ieeeStatus = 17; break;
                case 12: hal.nativeStateError = 5; break;
                case 13: ++hal.com.sc_generation; break;
                case 14: hal.ic.ic_bss = nullptr; break;
                case 15: node.ni_bssid[5] = 1; break;
                case 16: node.ni_rsnie_tlv = nullptr; break;
                case 17: node.ni_rsnie_tlv_len = 0; break;
                case 18: node.ni_chan = nullptr; break;
                case 19: node.ni_chan = IEEE80211_CHAN_ANYC; break;
                case 20: node.channel.band = 6; break;
                case 21: node.ni_esslen = 33; break;
                case 22: node.ni_rsnie_tlv_len = kMaxInformationElements + 1; break;
                case 23: ies[1] = 250; break;
            }
            std::vector<uint8_t> output(kMaxBeaconMessage + 16, 0xa5);
            auto *buffer = output.data() + alignment;
            assert(interface.getSequoiaBSSInfo(nullptr) == kIOReturnBadArgument);
            const auto result = interface.getSequoiaBSSInfo(buffer);
            assert((result == kIOReturnSuccess) == (fault == 0));
            for (unsigned i = 0; i < alignment; ++i) assert(output[i] == 0xa5);
            for (unsigned i = alignment + kMaxBeaconMessage; i < output.size(); ++i) assert(output[i] == 0xa5);
            if (!fault) {
                BeaconMetadata metadata;
                memcpy(&metadata, buffer, sizeof(metadata));
                assert(metadata.ieLength == sizeof(ies) && metadata.ssidLength == 3);
                assert(!memcmp(metadata.ssid, node.ni_essid, 3) && !memcmp(metadata.bssid, node.ni_bssid, 6));
                assert(metadata.rssi == -55 && metadata.channelSpec == 0x1001);
                assert(metadata.flags == 0x4002);
                assert(!memcmp(buffer + sizeof(metadata), ies, sizeof(ies)));
                for (unsigned i = sizeof(metadata) + sizeof(ies); i < kMaxBeaconMessage; ++i) assert(!buffer[i]);
            }
            ++traces;
        }
    }
    unsigned extendedTraces = 0;
    for (unsigned fault = 0; fault < 22; ++fault) {
        for (unsigned alignment = 0; alignment < 8; ++alignment) {
            Owner owner; ItlIwm hal; ieee80211_node node;
            AirportItlwmSkywalkInterface interface{&owner, &hal};
            hal.ic.ic_bss = &node;
            uint8_t ies[] = {0,1,'a',48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
            node.ni_rsnie_tlv = ies; node.ni_rsnie_tlv_len = sizeof(ies);
            auto &j = owner.nativeJoin;
            j.busy = j.started = j.associationReady = true; j.generation = 1;
            assert(hal.nativeJoinProgress.begin(node.ni_bssid, 1));
            switch (fault) {
                case 1: interface.instance = nullptr; break;
                case 2: owner.loop.gated = false; break;
                case 3: owner.available = false; break;
                case 4: interface.fHalService = nullptr; break;
                case 5: j.busy = false; break;
                case 6: j.started = false; break;
                case 7: j.cancel = true; break;
                case 8: j.error = 5; break;
                case 9: j.drained = true; break;
                case 10: j.associationReady = false; break;
                case 11: j.association.ieeeStatus = 17; break;
                case 12: hal.nativeStateError = 5; break;
                case 13: ++hal.com.sc_generation; break;
                case 14: hal.ic.ic_bss = nullptr; break;
                case 15: node.ni_bssid[5] = 1; break;
                case 16: node.ni_rsnie_tlv = nullptr; break;
                case 17: --node.ni_rsnie_tlv_len; break;
                case 18: hal.ic.ic_state = 0; break;
                case 19: node.ni_rates.rs_nrates = 16; break;
                case 20: ies[3] = 49; break; // no associated RSN
                case 21: node.ni_rates.rs_rates[0] = 0; break;
            }
            std::vector<uint8_t> output(0x1e0 + 16, 0xa5);
            auto *buffer = output.data() + alignment;
            assert(interface.getSequoiaExtendedBSSInfo(nullptr) == kIOReturnBadArgument);
            const auto result = interface.getSequoiaExtendedBSSInfo(buffer);
            assert((result == kIOReturnSuccess) == (fault == 0));
            for (unsigned i = 0; i < output.size(); ++i)
                if (fault || i < alignment || i >= alignment + 0x1e0) assert(output[i] == 0xa5);
            if (!fault) {
                // Fixed stock consumer offsets, independent of the C++ struct.
                assert(buffer[4] == 3 && buffer[5] == 0);
                assert(buffer[0xc] == 6 && buffer[0x10] == 1);
                assert(buffer[0x18] == 12 && buffer[0x24] == 54);
                assert(buffer[0xc0] == 0xff && buffer[0xc1] == 0);
                assert(buffer[0xd0] == 0xfd && buffer[0xd1] == 0xff);
                assert(buffer[0xd8] == 0xff && buffer[0xd9] == 0xff);
                assert(buffer[0xdc] == 0 && !memcmp(buffer + 0xdd, ies + 3, 22));
                for (unsigned i = 0xdd + 22; i < 0x1e0; ++i) assert(buffer[i] == 0);
                // Negotiated HE widths and legacy-only modes must not invent
                // supported streams. No physical AX210 is modeled here.
                node.ni_flags = IEEE80211_NODE_HE;
                hal.ic.ic_he_mcs_nss_supp.tx_mcs_80 = 0xfffd;
                for (auto width : {80u,160u,8080u}) {
                    node.ni_chw = width;
                    assert(interface.getSequoiaExtendedBSSInfo(buffer) == 0);
                    assert(buffer[0xd0] == 0xff && buffer[0xc0] == 0);
                    assert(buffer[0xd8] == (width == 80 ? 0xfd : width == 160 ? 0xfe : 0xff));
                }
            }
            ++extendedTraces;
        }
    }
    // Complete 257-byte IE fits exactly; duplicates/trailing truncation fail
    // without modifying output. These boundaries cannot be inferred from scans.
    {
        uint8_t rates[] = {0x8c}, ht[10] = {}, ies[259] = {48,255,1,0};
        uint8_t out[0x1e0]; memset(out, 0xa5, sizeof(out));
        assert(encodeExtendedBss(rates,1,ht,0xffff,0xffff,ies,257,out));
        memset(out,0xa5,sizeof(out));
        assert(!encodeExtendedBss(rates,1,ht,0xffff,0xffff,ies,258,out));
        ies[257] = 48; ies[258] = 0;
        assert(!encodeExtendedBss(rates,1,ht,0xffff,0xffff,ies,259,out));
        for (auto byte : out) assert(byte == 0xa5);
    }
    for (unsigned a = 0; a < 3; ++a) for (unsigned b = 0; b < 3; ++b) {
        Owner owner; AirportItlwmSkywalkInterface interface{&owner, nullptr};
        uint8_t flags[2] = {static_cast<uint8_t>(a),static_cast<uint8_t>(b)};
        const auto expected = a > 1 || b > 1 ? kIOReturnBadArgument : a ? kIOReturnUnsupported : kIOReturnSuccess;
        assert(interface.setSequoiaFastLane(flags) == expected);
        assert(owner.nativeJoin.diagnostics.fastLaneResult == static_cast<uint32_t>(expected));
        owner.available = false; assert(interface.setSequoiaFastLane(flags) == kIOReturnNotReady);
        assert(interface.setSequoiaFastLane(nullptr) == kIOReturnBadArgument);
    }
    // Slot 589 is BCM's ARP/GARP keepalive configuration. The Intel path
    // validates the audited scalar fields and acknowledges the request without
    // claiming an Intel firmware offload implementation.
    for (unsigned mode = 0; mode < 2; ++mode) {
        Owner owner; AirportItlwmSkywalkInterface interface{&owner, nullptr};
        uint8_t payload[0x14] = {};
        memcpy(payload + 8, &mode, sizeof(mode));
        payload[4] = 1; payload[5] = 1;
        assert(interface.setSequoiaArpMode(payload) == kIOReturnSuccess);
        assert(owner.configurationSetters == 1 && owner.lastConfigurationSetter == 589);
    }
    {
        Owner owner; AirportItlwmSkywalkInterface interface{&owner, nullptr};
        uint8_t payload[0x14] = {};
        uint32_t invalid = 2; memcpy(payload + 8, &invalid, sizeof(invalid));
        assert(interface.setSequoiaArpMode(payload) == kIOReturnUnsupported);
        payload[4] = 2; invalid = 0; memcpy(payload + 8, &invalid, sizeof(invalid));
        assert(interface.setSequoiaArpMode(payload) == kIOReturnBadArgument);
        assert(interface.setSequoiaArpMode(nullptr) == kIOReturnBadArgument);
        interface.instance = nullptr;
        assert(interface.setSequoiaArpMode(payload) == kIOReturnNotReady);
    }
    std::printf("Native extended-BSS: %u ownership/failure/bounds traces, negotiated rates/MCS/RSN, HE widths, Fastlane refusal and ARP-mode compatibility tests passed; HAL mocked\n", extendedTraces);
    std::printf("Native current-BSS controller: %u actual query/encoder ownership, generation, binary SSID, IE and unaligned-output traces passed; HAL mocked\n", traces);
}
