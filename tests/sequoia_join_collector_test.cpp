#include <Airport/SequoiaSecurity.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <vector>
#include <Airport/SequoiaJoinRequest.h>
#include <Airport/SequoiaJoinEvents.h>
#include <Airport/SequoiaJoinCandidate.h>
#include <Airport/SequoiaScanPlan.h>
#include <HAL/IwmScanFrame.h>
#include <HAL/ItlJoinEvent.h>
#include <HAL/ItlNativeScan.h>
#define IEEE80211_STA_ONLY 1
#define AIRPORT 1
#define IO80211FAMILY_V2 1
#define __MAC_15_0 150000
#define __IO80211_TARGET __MAC_15_0
#include "sequoia_join_bsd_types.inc"
#define DPRINTF(args) ((void)0)
#define XYLog(...) ((void)0)
#define isclr(map, i) (!((map)[(i) / 8] & (1u << ((i) % 8))))
#define setbit(map, i) ((map)[(i) / 8] |= 1u << ((i) % 8))
#define clrbit(map, i) ((map)[(i) / 8] &= ~(1u << ((i) % 8)))
#define isset(map, i) (!isclr(map, i))
#define ISSET(value, flags) ((value) & (flags))
#define nitems(array) (sizeof(array) / sizeof((array)[0]))
#define mtod(packet, type) reinterpret_cast<type>((packet)->data())
using mbuf_t = std::vector<uint8_t> *;
static size_t mbuf_len(mbuf_t packet) { return packet->size(); }
constexpr int MBUF_DONTWAIT = 0;
static unsigned packetFailure = 0, packetOwners = 0, pullupCalls = 0;
static int mbuf_allocpacket(int, size_t length, unsigned *chunks, mbuf_t *out) {
    if (packetFailure == 1) return ENOMEM;
    if (chunks) { assert(*chunks == 1); *chunks = 1; }
    *out = new std::vector<uint8_t>(length); ++packetOwners; return 0;
}
static int mbuf_copyback(mbuf_t packet, size_t offset, size_t length, const void *bytes, int) {
    if (packetFailure == 2) return ENOMEM;
    assert(offset + length <= packet->size()); memcpy(packet->data() + offset, bytes, length);
    if (packetFailure == 3) packet->resize(length - 1);
    return 0;
}
static mbuf_t mbuf_next(mbuf_t packet) { return packetFailure == 4 ? packet : nullptr; }
static void mbuf_freem(mbuf_t packet) { assert(packetOwners); --packetOwners; delete packet; }
static int mbuf_pullup(mbuf_t *packet, size_t length) {
    ++pullupCalls;
    // Audited 24G830 external-cluster path rejects > MHLEN (88), even
    // when the input is already contiguous. All lengths > MLEN (224) fail.
    if (length > 88) { mbuf_freem(*packet); *packet = nullptr; return ENOMEM; }
    assert(length <= (*packet)->size()); return 0;
}
static uint64_t now = 1000;
static uint64_t airport_up_time() { return now; }
static int ieee80211_debug = 0;
static void ieee80211_print_essid(const uint8_t *, int) {}

struct ieee80211_channel { unsigned ic_flags = 0, ic_freq = 0; };
struct ieee80211_key { ieee80211_cipher k_cipher = IEEE80211_CIPHER_NONE; };
struct ieee80211_node {
    unsigned ni_associd = 0, ni_fails = 0, ni_rsn_supp_state = 0;
    unsigned ni_port_valid = 0, ni_replaycnt_ok = 0;
    uint8_t ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    ieee80211_key ni_pairwise_key;
    unsigned ni_assoc_fail = 0;
    uint8_t ni_macaddr[6] = {}, ni_pmkid[16] = {};
    ieee80211_cipher ni_rsncipher = IEEE80211_CIPHER_NONE;
    unsigned ni_refcnt = 0;
    ieee80211_channel *ni_chan = nullptr;
    unsigned ni_flags = 0, ni_state = 0, ni_erp = 0, ni_capinfo = 0;
    unsigned ni_htop0 = 0, ni_htop1 = 0, ni_dtimcount = 0, ni_dtimperiod = 0;
    unsigned ni_htcaps = 0, ni_ampdu_param = 0, ni_max_rxrate = 0, ni_tx_mcs_set = 0;
    unsigned ni_htxcaps = 0, ni_txbfcaps = 0, ni_aselcaps = 0, ni_primary_chan = 0, ni_htop2 = 0;
    uint8_t ni_rxmcs[10] = {}, ni_basic_mcs[16] = {};
    unsigned ni_vhtcaps = 0, ni_vht_basicmcs = 0, ni_vht_chan1 = 0, ni_vht_chan2 = 0, ni_vht_chanwidth = 0;
    ieee80211_vht_mcs_info ni_vht_mcsinfo = {};
    ieee80211_he_cap_elem ni_he_cap_elem = {};
    ieee80211_he_mcs_nss_supp ni_he_mcs_nss_supp = {};
    uint8_t ni_ppe_thres[IEEE80211_HE_PPE_THRES_MAX_LEN] = {}, ni_he_optional[8] = {};
    unsigned ni_he_oper_params = 0, ni_he_oper_nss_set = 0;
    uint64_t ni_age_ts = 0;
    unsigned ni_rsnprotos = 0, ni_supported_rsnprotos = 0, ni_rsnakms = 0, ni_supported_rsnakms = 0;
    unsigned ni_rsnciphers = 0, ni_rsncaps = 0;
    ieee80211_cipher ni_rsngroupcipher = IEEE80211_CIPHER_NONE, ni_rsngroupmgmtcipher = IEEE80211_CIPHER_NONE;
    uint8_t *ni_rsnie_tlv = nullptr, *ni_rsnie = nullptr;
    uint32_t ni_rsnie_tlv_len = 0;
    uint8_t ni_essid[32] = {}, ni_bssid[6] = {}, ni_tstamp[8] = {};
    uint8_t ni_esslen = 0;
    unsigned ni_rstamp = 0, ni_intval = 0;
    int ni_rssi = 0;
    ieee80211_rateset ni_rates = {};
};
struct _ifnet { unsigned if_flags = 0; };
struct ieee80211com {
    SequoiaWCL::TkipCountermeasures ic_native_tkip;
    bool ic_native_pmf = false;
    unsigned ic_max_nnodes = 512;
    unsigned ic_nnodes = 0;
    uint8_t ic_max_rssi = 100;
    _ifnet ic_if;
    unsigned ic_assoc_status = 0;
    unsigned ic_deauth_reason = 0;
    int ic_edca_updtcount = 0;
    void (*ic_event_handler)(ieee80211com *, int, void *) = nullptr;
    void (*ic_delete_key)(ieee80211com *, ieee80211_node *, ieee80211_key *) = nullptr;
    int ic_des_esslen = 0, ic_fixed_rate = -1;
    uint8_t ic_des_essid[32] = {}, ic_des_bssid[6] = {};
    ieee80211_channel *ic_des_chan = IEEE80211_CHAN_ANYC;
    unsigned ic_modecaps = 0x7f, ic_bgscan_timeout = 0, ic_xflags = 0;
    ieee80211_rateset ic_sup_rates[IEEE80211_MODE_MAX] = {};
    void (*ic_node_copy)(ieee80211com *, ieee80211_node *, const ieee80211_node *) = nullptr;
    int (*ic_newstate)(ieee80211com *, ieee80211_state, int) = nullptr;
    ieee80211_key ic_nw_keys[4];
    ieee80211_state ic_state = IEEE80211_S_INIT;
    ieee80211_opmode ic_opmode = IEEE80211_M_STA;
    ieee80211_phymode ic_curmode = IEEE80211_MODE_11G;
    unsigned ic_flags = 0, ic_caps = IEEE80211_C_RSN, ic_htcaps = 0, ic_mgt_timer = 0;
    uint8_t ic_chan_avail[32] = {}, ic_chan_active[32] = {};
    ieee80211_channel ic_channels[256];
    ieee80211_node *ic_bss = nullptr;
    void (*ic_updateprot)(ieee80211com *) = nullptr;
    void (*ic_update_chw)(ieee80211com *) = nullptr;
    void (*ic_updatedtim)(ieee80211com *) = nullptr;
    struct { unsigned is_rx_elem_toosmall = 0, is_rx_badchan = 0, is_rx_chanmismatch = 0;
             unsigned is_ht_prot_change = 0, is_rx_rstoobig = 0;
             unsigned is_rx_mgtdiscard = 0, is_rx_auth_fail = 0, is_rx_assoc_norate = 0, is_rx_bad_auth = 0;
             unsigned is_rx_deauth = 0, is_rx_disassoc = 0; } ic_stats;
    unsigned ic_rsnprotos = 0, ic_rsnakms = 0, ic_rsnciphers = 0;
    ieee80211_cipher ic_rsngroupcipher = IEEE80211_CIPHER_NONE;
    uint8_t ic_psk[32] = {};
};
#include "sequoia_join_bsd_functions.inc"

static ieee80211_node cached;
static bool hasCached = false, failNode = false, failIE = false;
static unsigned hardwareCalls = 0;
static void clearCache() {
    free(cached.ni_rsnie_tlv); free(cached.ni_rsnie); cached = {}; hasCached = false;
}
static ieee80211_node *ieee80211_find_node(ieee80211com *, const uint8_t *address) {
    return hasCached && !memcmp(address, cached.ni_macaddr, 6) ? &cached : nullptr;
}
static ieee80211_node *ieee80211_alloc_node(ieee80211com *ic, const uint8_t *address) {
    if (failNode) return nullptr;
    memcpy(cached.ni_macaddr, address, 6); cached.ni_state = IEEE80211_STA_CACHE;
    ic->ic_nnodes = 1;
    hasCached = true; return &cached;
}
static unsigned ieee80211_chan2ieee(ieee80211com *ic, ieee80211_channel *channel) { return channel - ic->ic_channels; }
static void ieee80211_setup_htcaps(ieee80211_node *, const uint8_t *, uint8_t) {}
static int ieee80211_setup_htop(ieee80211_node *, const uint8_t *, uint8_t, int) { return 0; }
static void ieee80211_setup_vhtcaps(ieee80211com *, ieee80211_node *, const uint8_t *) {}
static void ieee80211_setup_vhtopmode(ieee80211_node *, const uint8_t *) {}
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "little-endian fixture");
#define le32toh(value) (value)
#define le16toh(value) (value)
#define DIV_ROUND_UP(a, b) (((a) + (b) - 1) / (b))
static uint8_t hweight8(uint8_t value) { return __builtin_popcount(value); }
#include "sequoia_join_he_functions.inc"
static int ieee80211_parse_edca_params(ieee80211com *, const uint8_t *) { ++hardwareCalls; return 0; }
static int ieee80211_parse_wmm_params(ieee80211com *, const uint8_t *) { ++hardwareCalls; return 0; }
static void ieee80211_set_shortslottime(ieee80211com *, int) { ++hardwareCalls; }
static void ieee80211_ht_negotiate(ieee80211com *, ieee80211_node *) {}
static void ieee80211_vht_negotiate(ieee80211com *, ieee80211_node *) {}
static void ieee80211_he_negotiate(ieee80211com *, ieee80211_node *) {}
static void ieee80211_sta_set_rx_nss(ieee80211com *, ieee80211_node *) {}
static void ieee80211_reset_erp(ieee80211com *) {}
static unsigned assocEvents = 0, authEvents = 0, rejectedEvents = 0, disconnectEvents = 0;
static int linkState = LINK_STATE_DOWN;
static void ieee80211_set_link_state(ieee80211com *, int state) { linkState = state; }
static ItlJoin::Event lastEvent = {};
static void assocEvent(ieee80211com *ic, int code, void *data) {
    assert(code == IEEE80211_EVT_NATIVE_JOIN && data);
    lastEvent = *static_cast<const ItlJoin::Event *>(data);
    assert(!memcmp(lastEvent.bssid, ic->ic_bss->ni_bssid, 6));
    if (lastEvent.stage == ItlJoin::Stage::Auth) ++authEvents;
    if (lastEvent.stage == ItlJoin::Stage::Deauth || lastEvent.stage == ItlJoin::Stage::Disassoc) ++disconnectEvents;
    if (lastEvent.stage == ItlJoin::Stage::Assoc && !lastEvent.status) ++assocEvents;
    if (lastEvent.status) ++rejectedEvents;
}
static int splnet() { return 0; }
static void splx(int) {}
struct ieee80211_pmk { uint8_t pmk_pmkid[16]; };
static ieee80211_pmk *ieee80211_pmksa_find(ieee80211com *, ieee80211_node *, const uint8_t *) { return nullptr; }
static int modeError = 0, queueError = 0, queuedState = -1, queuedArg = 0, copyFault = 0;
static int ieee80211_setmode(ieee80211com *ic, ieee80211_phymode mode) {
    if (modeError) return modeError;
    ic->ic_curmode = mode;
    memcpy(ic->ic_chan_active, ic->ic_chan_avail, sizeof(ic->ic_chan_active));
    return 0;
}
static void timeout_del(unsigned *timer) { *timer = 0; }
static int queueState(ieee80211com *, ieee80211_state state, int arg) {
    if (queueError) return queueError;
    queuedState = state; queuedArg = arg; return 0;
}
static void ieee80211_save_ie_tlv(const uint8_t *src, uint8_t **out, uint32_t *outLength, uint32_t size) {
    free(*out); *out = nullptr; *outLength = 0;
    if (failIE) return;
    *out = static_cast<uint8_t *>(malloc(size)); assert(*out); memcpy(*out, src, size); *outLength = size;
}
static int ieee80211_save_ie(const uint8_t *src, uint8_t **out) {
    free(*out); *out = nullptr;
    if (failIE) return ENOMEM;
    *out = static_cast<uint8_t *>(malloc(src[1] + 2)); assert(*out); memcpy(*out, src, src[1] + 2); return 0;
}
static void copyNode(ieee80211com *, ieee80211_node *dst, const ieee80211_node *src) {
    free(dst->ni_rsnie); free(dst->ni_rsnie_tlv);
    *dst = *src; dst->ni_rsnie = dst->ni_rsnie_tlv = nullptr; dst->ni_rsnie_tlv_len = 0;
    if (src->ni_rsnie && copyFault != 1) ieee80211_save_ie(src->ni_rsnie, &dst->ni_rsnie);
    if (src->ni_rsnie_tlv && copyFault != 2)
        ieee80211_save_ie_tlv(src->ni_rsnie_tlv, &dst->ni_rsnie_tlv, &dst->ni_rsnie_tlv_len, src->ni_rsnie_tlv_len);
    if (copyFault == 3) dst->ni_rsnie_tlv_len = 0;
}
// The upstream parser retains IBSS-only bookkeeping in station-only builds.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-but-set-variable"
#include "sequoia_join_collector_functions.inc"
#pragma clang diagnostic pop

class ItlIwm {
public:
    struct Loop {
        bool gate = true, thread = false;
        bool inGate() const { return gate; }
        bool onThread() const { return thread; }
    } loop;
    Loop *getMainWorkLoop() { return &loop; }
    bool leased = false, denied = false, trial = false, nativeNet80211Attached = true;
    unsigned leaseDepth = 0;
    bool commandTransportReady = true;
    int nativeStateError = 0;
    ItlJoin::Progress nativeJoinProgress;
    SequoiaWCL::JoinCandidateDiagnostic nativeCandidateDiagnostic;
    ItlScan::CacheDiagnostic nativeCacheDiagnostic;
    const SequoiaWCL::ScanPlan *nativeScanPlan = nullptr;
    ItlScan::LegacyPhy nativeScanCachePhy;
    int nativeScanCancel = 0;
    void iwm_native_scan_cache_rx(uint16_t, const void *, size_t);
    bool isHardwareTrial() const { return trial; }
    class FirmwareLease {
        ItlIwm *owner;
        bool acquired;
    public:
        explicit FirmwareLease(ItlIwm *driver) : owner(driver), acquired(!driver->denied)
        { if (acquired) { ++owner->leaseDepth; owner->leased = true; } }
        ~FirmwareLease() { if (acquired && !--owner->leaseDepth) owner->leased = false; }
        explicit operator bool() const { return acquired; }
    };
    struct { bool active = false; bool valid() const { return active; } } nativeScanSink;
    struct {
        ieee80211com sc_ic;
        ieee80211_state ns_nstate = IEEE80211_S_INIT;
        int sc_generation = 7;
        unsigned sc_device_family = IWM_DEVICE_FAMILY_7000, sc_flags = 0;
        bool sc_mqrx_supported = false;
        iwm_ucode_type sc_uc_current = IWM_UCODE_TYPE_REGULAR;
    } com;
    int iwm_native_join_candidate(const SequoiaWCL::JoinRequestSnapshot &, size_t, ieee80211_node **);
    int iwm_native_join_security(const SequoiaWCL::JoinRequestSnapshot &);
    int iwm_native_join_start(const SequoiaWCL::JoinRequestSnapshot &, size_t);
};
#include "../itlwm/hal_iwm/native_join_candidate_sequoia.inc"
#include "../itlwm/hal_iwm/native_join_security_sequoia.inc"
#include "../itlwm/hal_iwm/native_join_start_sequoia.inc"
#include "../itlwm/hal_iwm/native_scan_cache_sequoia.inc"

// Execute the actual second HAL's collector against the same BSD/mbuf boundary.
#define IWX_MIN_DBM -100
struct iwx_softc { ieee80211com sc_ic; };
class ItlIwx : public ItlIwm {
public:
    bool nativeDetached = false;
    int iwx_native_join_candidate(const SequoiaWCL::JoinRequestSnapshot &, size_t, ieee80211_node **);
    void iwx_native_scan_cache_mpdu(iwx_softc *, const uint8_t *, size_t, const ItlScan::LegacyPhy &);
};
#include "sequoia_iwx_cache.inc"
#include "sequoia_iwx_join_candidate.inc"

int main()
{
    ItlIwm driver;
    auto &ic = driver.com.sc_ic;
    ieee80211_node local;
    ic.ic_bss = &local;
    ic.ic_node_copy = copyNode;
    ic.ic_newstate = queueState;
    for (auto &rates : ic.ic_sup_rates) { rates.rs_nrates = 2; rates.rs_rates[0] = 0x82; rates.rs_rates[1] = 0x84; }
    local.ni_chan = &ic.ic_channels[1];
    ic.ic_channels[1].ic_freq = 2412;
    ic.ic_channels[1].ic_flags = IEEE80211_CHAN_2GHZ;
    setbit(ic.ic_chan_avail, 1);
    ieee80211_rxinfo info = {}; info.rxi_chan = 1; info.rxi_rssi = 45;
    std::vector<uint8_t> beacon(36, 0);
    beacon[0] = 0x80; beacon[10] = beacon[16] = 2;
    beacon[32] = 100; beacon[34] = IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_PRIVACY;
    const uint8_t ies[] = {0,3,0,'a','b',1,2,0x82,0x84,3,1,1,
        48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
    beacon.insert(beacon.end(), ies, ies + sizeof(ies));
    // Native cache collection uses available NVM channels even when the
    // current PHY mode's active map excludes the channel. It never changes state.
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(hasCached && ic.ic_state == IEEE80211_S_INIT && !hardwareCalls);
    assert(cached.ni_esslen == 3 && !memcmp(cached.ni_essid, "\0ab", 3));
    assert(cached.ni_rsnprotos == IEEE80211_PROTO_RSN && cached.ni_rsnakms == IEEE80211_AKM_PSK);
    assert(cached.ni_rsnciphers == IEEE80211_CIPHER_CCMP && cached.ni_rsnie);
    assert(cached.ni_rates.rs_nrates == 2 && cached.ni_rates.rs_rates[0] == 0x82);
    assert(cached.ni_age_ts == now && cached.ni_rssi == 45);
    // Connected collection updates only neighbour cache nodes, not the
    // serving peer's negotiated state or hardware configuration.
    clearCache();
    ic.ic_state = IEEE80211_S_RUN;
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(hasCached && ic.ic_state == IEEE80211_S_RUN && !hardwareCalls);
    auto *serving = ic.ic_bss;
    ic.ic_bss = &cached;
    const auto flags = cached.ni_flags;
    const auto stamp = cached.ni_age_ts;
    ++now;
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(cached.ni_flags == flags && cached.ni_age_ts == stamp && !hardwareCalls);
    ic.ic_bss = serving;
    ic.ic_state = IEEE80211_S_INIT;
    --now;
    SequoiaWCL::JoinRequest request = {};
    request.authLower = APPLE80211_AUTHTYPE_OPEN;
    request.authUpper = APPLE80211_AUTHTYPE_WPA2_PSK;
    const uint8_t selected[] = {48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
    memcpy(request.rsn, selected, sizeof(selected)); request.rsnLength = sizeof(selected);
    request.ssidLength = 3;
    memcpy(request.ssid, "\0ab", 3);
    request.candidateCount = 1;
    request.candidates[0].bssid[0] = 2;
    request.candidates[0].channelSpec = 0x1001;
    SequoiaWCL::JoinRequestSnapshot snapshot;
    auto select = [&](const SequoiaWCL::JoinRequest &wire, size_t index = 0) {
        assert(snapshot.capture(&wire, sizeof(wire)));
        ieee80211_node *result = nullptr;
        const int error = driver.iwm_native_join_candidate(snapshot, index, &result);
        assert(!driver.leased && !hardwareCalls);
        if (error) assert(!result && !cached.ni_refcnt);
        else {
            assert(result == &cached && cached.ni_refcnt == 1);
            ieee80211_unref_node(&result);
            assert(!result && !cached.ni_refcnt);
        }
        return error;
    };
    // Advertise WPA/TKIP alongside RSN with CCMP+TKIP pairwise choices.
    // Both real HAL candidate methods must accept the WPA2/CCMP path; the
    // WPA vendor IE must not cause a blanket mixed-mode rejection.
    auto mixed = beacon;
    mixed[36 + 12 + 1] += 4; // RSN length: add second pairwise selector
    mixed[36 + 12 + 8] = 2;
    const uint8_t tkip[] = {0,15,172,2};
    mixed.insert(mixed.begin() + 36 + 12 + 14, tkip, tkip + 4);
    const uint8_t wpa[] = {221,22,0,80,242,1,1,0,0,80,242,2,1,0,0,80,242,2,1,0,0,80,242,2};
    mixed.insert(mixed.end(), wpa, wpa + sizeof(wpa));
    auto selectBoth = [&](int expected) {
        assert(select(request) == expected);
        ItlIwx iwx;
        iwx.com = driver.com;
        auto *originalChannel = cached.ni_chan;
        cached.ni_chan = &iwx.com.sc_ic.ic_channels[1];
        ieee80211_node *result = nullptr;
        assert(snapshot.capture(&request, sizeof(request)));
        assert(iwx.iwx_native_join_candidate(snapshot, 0, &result) == expected);
        if (!expected) { assert(result == &cached); ieee80211_unref_node(&result); }
        else assert(!result);
        assert(!cached.ni_refcnt && !iwx.leased);
        cached.ni_chan = originalChannel;
    };
    // WPA2/WPA3 transition beacons: additional SAE selectors, in either
    // order, must not hide the usable WPA2 PSK/CCMP suite. No SAE execution.
    for (unsigned order = 0; order < 2; ++order) {
        auto transition = beacon;
        const size_t rsnOffset = 36 + 12;
        transition[rsnOffset + 1] += 4;
        transition[rsnOffset + 14] = 2;
        const uint8_t sae[] = {0,15,172,8};
        const size_t insertAt = rsnOffset + (order ? 16 : 20);
        transition.insert(transition.begin() + insertAt, sae, sae + sizeof(sae));
        transition[rsnOffset + 24] = 0x80; // MFPC, not MFPR.
        clearCache(); ieee80211_collect_bss(&ic, &transition, &info, 0);
        assert(cached.ni_rsnakms & IEEE80211_AKM_PSK);
        assert(cached.ni_rsnciphers == IEEE80211_CIPHER_CCMP);
        selectBoth(0);
        transition[rsnOffset + 24] = 0xc0; // Cannot ignore required PMF.
        clearCache(); ieee80211_collect_bss(&ic, &transition, &info, 0);
        selectBoth(EOPNOTSUPP);
        // Remove the PSK option while preserving well-formed SAE-only RSN.
        const size_t pskAt = rsnOffset + (order ? 20 : 16);
        transition.erase(transition.begin() + pskAt, transition.begin() + pskAt + 4);
        transition[rsnOffset + 1] -= 4;
        transition[rsnOffset + 14] = 1;
        clearCache(); ieee80211_collect_bss(&ic, &transition, &info, 0);
        assert(!(cached.ni_rsnakms & IEEE80211_AKM_PSK));
        selectBoth(EOPNOTSUPP);
    }
    puts("Actual BSD/IWM/IWX WPA2/WPA3 transition: both AKM orders select PSK/CCMP; SAE-only and unmet required PMF rejected");
    clearCache(); ieee80211_collect_bss(&ic, &mixed, &info, 0);
    assert(cached.ni_supported_rsnprotos == (IEEE80211_PROTO_RSN | IEEE80211_PROTO_WPA));
    assert(cached.ni_rsnprotos == IEEE80211_PROTO_RSN);
    assert(cached.ni_rsnciphers == (IEEE80211_CIPHER_CCMP | IEEE80211_CIPHER_TKIP));
    assert(cached.ni_rsngroupcipher == IEEE80211_CIPHER_CCMP);
    selectBoth(0);
    mixed[36 + 12 + 7] = 2; // RSN group TKIP is mandatory, not an optional choice
    clearCache(); ieee80211_collect_bss(&ic, &mixed, &info, 0);
    selectBoth(EOPNOTSUPP);
    mixed[36 + 12 + 7] = 4;
    mixed[36 + 12 + 13] = 2; // both pairwise selectors TKIP: no usable CCMP
    clearCache(); ieee80211_collect_bss(&ic, &mixed, &info, 0);
    selectBoth(EOPNOTSUPP);
    clearCache(); ieee80211_collect_bss(&ic, &beacon, &info, 0);
    puts("Actual BSD/IWM/IWX mixed WPA+RSN admission: accept selected WPA2/CCMP, reject AP/request cipher mismatches; synthetic beacons, no radio I/O");
    assert(!select(request));
    auto transitionRequest = request;
    transitionRequest.candidates[0].saePKCapable = 1;
    assert(select(transitionRequest) == 0);
    assert(driver.nativeCandidateDiagnostic.mask == 0);
    assert(driver.nativeCandidateDiagnostic.ageMs == 0);
    assert(select(request, 1) == EINVAL);
    unsigned candidateRejections = 0;
    for (unsigned scenario = 0; scenario < 32; ++scenario) {
        auto bad = request;
        const auto before = cached;
        switch (scenario) {
            case 0: bad.ssidLength = 0; break;
            case 1: bad.ssid[2] ^= 1; break;
            case 2: bad.authLower = APPLE80211_AUTHTYPE_SHARED; break;
            case 3: bad.authUpper = APPLE80211_AUTHTYPE_WPA_PSK; break;
            case 4: bad.authUpperExtended = 1; break;
            case 5: bad.candidates[0].bssid[0] = 1; break;
            case 6: bad.candidates[0].bssid[0] = 4; break;
            case 7: bad.candidates[0].saePKCapable = 1;
                bad.authUpper = APPLE80211_AUTHTYPE_WPA3_SAE; break;
            case 8: bad.candidates[0].oweTransitionBssid[0] = 2; break;
            case 9: bad.candidates[0].channelSpec = 0xd001; break;
            case 10: bad.candidates[0].channelSpec = 0x1000; break;
            case 11: bad.candidates[0].channelSpec = 0x1801; break;
            case 12: bad.candidates[0].channelSpec = 0x1002; break;
            case 13: cached.ni_age_ts = 0; break;
            case 14: cached.ni_age_ts = now + 1; break;
            case 15: now += 30001; break;
            case 16: cached.ni_capinfo = IEEE80211_CAPINFO_IBSS; break;
            case 17: cached.ni_intval = 0; break;
            case 18: cached.ni_rates.rs_nrates = 0; break;
            case 19: cached.ni_rsnprotos = IEEE80211_PROTO_WPA; break;
            case 20: cached.ni_rsnakms = IEEE80211_AKM_8021X; break;
            case 21: cached.ni_rsnciphers = IEEE80211_CIPHER_TKIP; break;
            case 22: cached.ni_rsngroupcipher = IEEE80211_CIPHER_TKIP; break;
            case 23: cached.ni_rsncaps = IEEE80211_RSNCAP_MFPR; break;
            case 24: driver.loop.gate = false; break;
            case 25: driver.loop.thread = true; break;
            case 26: driver.denied = true; break;
            case 27: driver.trial = true; break;
            case 28: driver.nativeScanSink.active = true; break;
            case 29: driver.nativeNet80211Attached = false; break;
            case 30: ic.ic_state = IEEE80211_S_AUTH; break;
            case 31: cached.ni_state = IEEE80211_STA_BSS; break;
        }
        assert(select(bad)); ++candidateRejections;
        cached = before; now = 1000;
        driver.loop = {}; driver.denied = driver.trial = false;
        driver.nativeScanSink.active = false; driver.nativeNet80211Attached = true;
        ic.ic_state = IEEE80211_S_INIT;
    }
    now += 30000; assert(!select(request)); now = 1000;
    const auto secured = cached;
    auto open = request; open.authUpper = 0;
    assert(select(open));
    cached.ni_capinfo &= ~IEEE80211_CAPINFO_PRIVACY;
    assert(select(open));
    cached.ni_supported_rsnprotos = 0;
    assert(!select(open)); cached = secured;
    ic.ic_channels[36].ic_freq = 5180;
    ic.ic_channels[36].ic_flags = IEEE80211_CHAN_5GHZ;
    setbit(ic.ic_chan_avail, 36);
    cached.ni_chan = &ic.ic_channels[36];
    auto fiveGHz = request; fiveGHz.candidates[0].channelSpec = 0xd024;
    assert(!select(fiveGHz)); cached = secured;
    auto join = request;
    join.key.cipher = APPLE80211_CIPHER_PMK; join.key.length = 32;
    memset(join.key.bytes, 0x5a, 32);
    join.rsnLength = sizeof(ies) - 12;
    memcpy(join.rsn, ies + 12, join.rsnLength);
    ic.ic_if.if_flags = IFF_RUNNING;
    auto attempt = [&] {
        assert(snapshot.capture(&join, sizeof(join)));
        int result = driver.iwm_native_join_start(snapshot, 0);
        assert(!driver.leased && !driver.leaseDepth && !cached.ni_refcnt);
        return result;
    };
    for (int fault = 1; fault <= 3; ++fault) {
        copyFault = fault; queuedState = -1;
        assert(attempt() == ENOMEM && queuedState == -1);
        assert(driver.nativeCandidateDiagnostic.stage == 6);
        for (auto byte : ic.ic_psk) assert(!byte);
        assert(!(ic.ic_flags & (IEEE80211_F_PSK | IEEE80211_F_DESBSSID)) && !ic.ic_des_esslen);
        assert(cached.ni_state == IEEE80211_STA_CACHE);
    }
    copyFault = 0; queueError = EBUSY;
    assert(attempt() == EBUSY && queuedState == -1); queueError = 0;
    modeError = EINVAL; assert(attempt() == EINVAL && queuedState == -1); modeError = 0;
    assert(driver.nativeCandidateDiagnostic.stage == 2);
    cached.ni_rsnciphers |= IEEE80211_CIPHER_TKIP;
    cached.ni_supported_rsnprotos |= IEEE80211_PROTO_WPA;
    assert(!attempt() && queuedState == IEEE80211_S_AUTH && queuedArg == IEEE80211_FC0_SUBTYPE_AUTH);
    assert(driver.nativeCandidateDiagnostic.stage == 7);
    assert(ic.ic_state == IEEE80211_S_INIT && cached.ni_state == IEEE80211_STA_BSS);
    assert(local.ni_rsncipher == IEEE80211_CIPHER_CCMP && local.ni_rsnakms == IEEE80211_AKM_PSK);
    assert(!memcmp(ic.ic_psk, join.key.bytes, 32));
    assert(ic.ic_des_chan == &ic.ic_channels[1] && ic.ic_des_esslen == 3);
    free(local.ni_rsnie); free(local.ni_rsnie_tlv); local = {};
    driver.nativeJoinProgress.clear(); // Model the owner's joined reset.
    local.ni_chan = &ic.ic_channels[1]; cached = secured;
    ieee80211_disable_rsn(&ic); ic.ic_flags = 0; memset(ic.ic_psk, 0, sizeof(ic.ic_psk));
    ic.ic_des_esslen = 0; ic.ic_des_chan = IEEE80211_CHAN_ANYC;
    clrbit(ic.ic_chan_active, 1);
    ++now; beacon[38] = 'x';
    ieee80211_collect_bss(&ic, &beacon, &info, 1);
    assert(!memcmp(cached.ni_essid, "xab", 3) && cached.ni_age_ts == now);
    cached.ni_flags = IEEE80211_NODE_HTCAP | IEEE80211_NODE_VHTCAP |
        IEEE80211_NODE_HT | IEEE80211_NODE_VHT | IEEE80211_NODE_HE |
        IEEE80211_NODE_HT_SGI20 | IEEE80211_NODE_HT_SGI40 |
        IEEE80211_NODE_VHT_SGI80 | IEEE80211_NODE_VHT_SGI160;
    cached.ni_htcaps = cached.ni_htop0 = cached.ni_vhtcaps = cached.ni_vht_chanwidth = 0xff;
    memset(cached.ni_rxmcs, 0xff, sizeof(cached.ni_rxmcs));
    memset(&cached.ni_he_cap_elem, 0xff, sizeof(cached.ni_he_cap_elem));
    cached.ni_he_oper_params = 0xffffffff;
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(!cached.ni_flags && !cached.ni_htcaps && !cached.ni_htop0 &&
           !cached.ni_vhtcaps && !cached.ni_vht_chanwidth && !cached.ni_he_oper_params);
    for (auto byte : cached.ni_rxmcs) assert(!byte);
    for (auto byte : cached.ni_he_cap_elem.phy_cap_info) assert(!byte);
    cached.ni_flags |= IEEE80211_NODE_QOS;
    const uint8_t qos[] = {12,1,0};
    beacon.insert(beacon.end(), qos, qos + sizeof(qos));
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(!hardwareCalls);
    // A probe response supplies a binary SSID; later hidden beacons must not
    // erase it. Unknown hidden APs still have no fabricated name.
    memset(beacon.data() + 38, 0, 3);
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(cached.ni_esslen == 3 && !memcmp(cached.ni_essid, "xab", 3));
    beacon.erase(beacon.begin() + 38, beacon.begin() + 41); beacon[37] = 0;
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(cached.ni_esslen == 3 && !memcmp(cached.ni_essid, "xab", 3));
    auto namedRequest = request; memcpy(namedRequest.ssid, "xab", 3);
    assert(!select(namedRequest));
    clearCache();
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(!cached.ni_esslen);
    assert(select(namedRequest) == ENOENT);
    assert(driver.nativeCandidateDiagnostic.mask == (SequoiaWCL::CandidateSsidLength | SequoiaWCL::CandidateSsidBytes));
    // Exercise the actual IWM RX wrapper, not only the BSD parser below it.
    SequoiaWCL::ScanPlan plan;
    SequoiaWCL::ScanRequest scan = {};
    scan.version = 1; scan.scanType = 2; scan.passiveDwell = 110;
    SequoiaWCL::Channel inventory[] = {
        {1,1,SequoiaWCL::Band2GHz | SequoiaWCL::Width20MHz},
        {1,40,SequoiaWCL::Band5GHz | SequoiaWCL::Width20MHz}};
    const uint8_t mac[6] = {2,1,2,3,4,5};
    assert(plan.prepare(&scan, sizeof(scan), inventory, 2, mac, nullptr, 0, false) == SequoiaWCL::ScanPlanStatus::Success);
    driver.nativeScanPlan = &plan; driver.nativeScanSink.active = true;
    uint8_t phy[68] = {}; phy[22] = 1; phy[28] = 45;
    driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_PHY_CMD, phy, sizeof(phy));
    auto rawBeacon = beacon;
    rawBeacon[37] = 3;
    rawBeacon.insert(rawBeacon.begin() + 38, {'x','a','b'});
    std::vector<uint8_t> mpdu(rawBeacon.size() + 8);
    mpdu[0] = rawBeacon.size() & 0xff; mpdu[1] = rawBeacon.size() >> 8;
    memcpy(mpdu.data() + 4, rawBeacon.data(), rawBeacon.size());
    mpdu[4 + rawBeacon.size()] = 3;
    for (packetFailure = 0; packetFailure <= 4; ++packetFailure) {
        clearCache();
        driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_MPDU_CMD, mpdu.data(), mpdu.size());
        assert(hasCached == (packetFailure == 0));
        assert(!packetOwners);
    }
    packetFailure = 0;
    for (unsigned length = 0; length < mpdu.size(); ++length) {
        clearCache();
        driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_MPDU_CMD, mpdu.data(), length);
        assert(!hasCached && !packetOwners);
    }
    mpdu[4 + rawBeacon.size()] = 1;
    driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_MPDU_CMD, mpdu.data(), mpdu.size());
    assert(!hasCached && !packetOwners);
    mpdu[4 + rawBeacon.size()] = 3;
    driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_MPDU_CMD, mpdu.data(), mpdu.size());
    assert(hasCached && cached.ni_esslen == 3 && !memcmp(cached.ni_essid, "xab", 3));
    // Match this boot's sequence on channel40 through the real RX adapter.
    ic.ic_channels[40].ic_freq = 5200;
    ic.ic_channels[40].ic_flags = IEEE80211_CHAN_5GHZ;
    setbit(ic.ic_chan_avail, 40);
    phy[22] = 40;
    driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_PHY_CMD, phy, sizeof(phy));
    for (size_t offset = 36; offset + 2 <= rawBeacon.size(); offset += rawBeacon[offset + 1] + 2)
        if (rawBeacon[offset] == IEEE80211_ELEMID_DSPARMS) rawBeacon[offset + 2] = 40;
    rawBeacon[0] = IEEE80211_FC0_SUBTYPE_PROBE_RESP;
    memcpy(mpdu.data() + 4, rawBeacon.data(), rawBeacon.size());
    driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_MPDU_CMD, mpdu.data(), mpdu.size());
    assert(cached.ni_chan == &ic.ic_channels[40]);
    // Follow the named response with both padded and zero-length hidden SSIDs.
    mpdu[4] = IEEE80211_FC0_SUBTYPE_BEACON;
    memset(mpdu.data() + 4 + 38, 0, 3);
    driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_MPDU_CMD, mpdu.data(), mpdu.size());
    mpdu.erase(mpdu.begin() + 42, mpdu.begin() + 45);
    mpdu[41] = 0;
    mpdu[0] = (mpdu.size() - 8) & 0xff; mpdu[1] = (mpdu.size() - 8) >> 8;
    driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_MPDU_CMD, mpdu.data(), mpdu.size());
    assert(cached.ni_esslen == 3 && !memcmp(cached.ni_essid, "xab", 3));
    driver.nativeScanSink.active = false; driver.nativeScanPlan = nullptr;
    namedRequest.candidates[0].channelSpec = 0xd028;
    assert(!select(namedRequest));
    assert(driver.nativeCandidateDiagnostic.mask == 0 && driver.nativeCandidateDiagnostic.channel == 40);
    // Real-world beacon lengths from this boot fail m_pullup unconditionally.
    // Feed complete, well-formed frames through the actual RX/cache path.
    driver.nativeScanSink.active = true; driver.nativeScanPlan = &plan;
    for (size_t length : {size_t(320), size_t(347), size_t(354), size_t(1024), size_t(2048)}) {
        auto large = rawBeacon;
        assert(large.size() < length - 2);
        while (large.size() < length) {
            size_t payload = length - large.size() - 2;
            if (payload > 250) payload = 250;
            if (length - large.size() - payload - 2 == 1) --payload;
            large.push_back(200); large.push_back(payload);
            large.resize(large.size() + payload, 0);
        }
        // Reproduce the old failure with the same mbuf boundary.
        mbuf_t old = nullptr;
        assert(!mbuf_allocpacket(MBUF_DONTWAIT, length, nullptr, &old));
        assert(mbuf_pullup(&old, length) == ENOMEM && !old && !packetOwners);
        std::vector<uint8_t> wire(length + 8);
        wire[0] = length & 255; wire[1] = length >> 8;
        memcpy(wire.data() + 4, large.data(), length); wire[4 + length] = 3;
        clearCache();
        const auto oldCalls = pullupCalls;
        driver.iwm_native_scan_cache_rx(IWM_REPLY_RX_MPDU_CMD, wire.data(), wire.size());
        assert(hasCached && !packetOwners && pullupCalls == oldCalls);
        assert(cached.ni_esslen == 3 && cached.ni_chan == &ic.ic_channels[40]);
        ItlIwx iwx;
        iwx_softc sc;
        sc.sc_ic = ic;
        iwx.nativeScanPlan = &plan; iwx.nativeScanSink.active = true;
        for (packetFailure = 0; packetFailure <= 4; ++packetFailure) {
            clearCache(); sc.sc_ic.ic_nnodes = 0;
            iwx.iwx_native_scan_cache_mpdu(&sc, large.data(), length, driver.nativeScanCachePhy);
            assert(hasCached == (packetFailure == 0));
            assert(!packetOwners && pullupCalls == oldCalls);
        }
        packetFailure = 0;
        assert(iwx.nativeCacheDiagnostic.parserCalls == 1 && iwx.nativeCacheDiagnostic.nodeHits == 1);
        auto backgroundPlan = plan;
        backgroundPlan.markAssociatedScan(1);
        iwx.nativeScanPlan = &backgroundPlan;
        sc.sc_ic.ic_state = IEEE80211_S_RUN;
        clearCache(); sc.sc_ic.ic_nnodes = 0;
        iwx.iwx_native_scan_cache_mpdu(&sc, large.data(), length, driver.nativeScanCachePhy);
        assert(hasCached && !packetOwners && !hardwareCalls);
        assert(iwx.nativeCacheDiagnostic.parserCalls == 2 && iwx.nativeCacheDiagnostic.nodeHits == 2);

    }
    assert(driver.nativeCacheDiagnostic.parserCalls && driver.nativeCacheDiagnostic.nodeHits);
    assert(driver.nativeCacheDiagnostic.allocationFailed == 1);
    assert(driver.nativeCacheDiagnostic.copyFailed == 1);
    assert(driver.nativeCacheDiagnostic.layoutFailed == 2);
    driver.nativeScanSink.active = false; driver.nativeScanPlan = nullptr;
    puts("Actual IWM/IWX scan cache: 320/347/354/1024/2048-byte frames survive audited pullup limits; allocation/copy/layout failures leak no buffers");
    for (unsigned length = 0; length < beacon.size(); ++length) {
        std::vector<uint8_t> shortFrame(beacon.begin(), beacon.begin() + length);
        clearCache();
        ieee80211_collect_bss(&ic, &shortFrame, &info, 0);
        assert(ic.ic_state == IEEE80211_S_INIT && !hardwareCalls);
    }
    clearCache(); failNode = true;
    ieee80211_collect_bss(&ic, &beacon, &info, 0); assert(!hasCached); failNode = false;
    failIE = true;
    ieee80211_collect_bss(&ic, &beacon, &info, 0);
    assert(hasCached && !cached.ni_rsnie && !cached.ni_rsnprotos); failIE = false;
    clearCache();
    printf("Actual candidate preflight/reference: 2.4/5 GHz, open/WPA2, binary SSID, freshness and %u rejection cases passed; hardware and tree lookup mocked\n", candidateRejections);
    for (unsigned scenario = 0; scenario < 5; ++scenario) {
        switch (scenario) {
            case 0: ic.ic_state = IEEE80211_S_AUTH; break;
            case 1: ic.ic_opmode = IEEE80211_M_MONITOR; break;
            case 2: info.rxi_chan = 0; break;
            case 3: clrbit(ic.ic_chan_avail, 1); break;
            case 4: ic.ic_channels[1].ic_freq = 0; break;
        }
        ieee80211_collect_bss(&ic, &beacon, &info, 0); assert(!hasCached && !hardwareCalls);
        ic.ic_state = IEEE80211_S_INIT; ic.ic_opmode = IEEE80211_M_STA;
        info.rxi_chan = 1; setbit(ic.ic_chan_avail, 1); ic.ic_channels[1].ic_freq = 2412;
    }
    // The unchanged legacy entry still obeys its PHY channel map.
    ieee80211_recv_probe_resp(&ic, &beacon, &local, &info, 0); assert(!hasCached);
    setbit(ic.ic_chan_active, 1); ic.ic_state = IEEE80211_S_SCAN;
    ieee80211_recv_probe_resp(&ic, &beacon, &local, &info, 0); assert(hasCached);
    clearCache();
    puts("Actual BSD beacon collector/parser/rates: NVM map, binary/hidden SSID, RSN, truncations, allocation faults and no cache-only hardware callbacks passed; node allocator and HT/VHT/HE helpers mocked");
    puts("Actual HAL join start with BSD matcher/rate selection/node join: nested ownership, 3 IE-copy faults, queue failure, PMK cleanup and explicit AUTH queueing passed; mode update/node-copy allocation/scheduler mocked");
    ic.ic_event_handler = assocEvent;
    std::vector<uint8_t> response(30, 0);
    response[0] = IEEE80211_FC0_SUBTYPE_ASSOC_RESP;
    response[24] = IEEE80211_CAPINFO_ESS;
    response[28] = 1; response[29] = 0xc0;
    memcpy(response.data() + 10, local.ni_bssid, 6);
    memcpy(response.data() + 16, local.ni_bssid, 6);
    const uint8_t rateIE[] = {1,2,0x82,0x84};
    response.insert(response.end(), rateIE, rateIE + sizeof(rateIE));
    auto receive = [&](std::vector<uint8_t> &frame, bool accepted) {
        assocEvents = rejectedEvents = hardwareCalls = 0; queuedState = -1;
        ic.ic_state = IEEE80211_S_ASSOC;
        ieee80211_recv_assoc_resp(&ic, &frame, &local, 0);
        assert(assocEvents == accepted);
        assert(queuedState == (accepted ? IEEE80211_S_RUN : -1));
        if (!accepted) assert(!hardwareCalls);
    };
    receive(response, true);
    local.ni_flags = IEEE80211_NODE_HTCAP | IEEE80211_NODE_HT | IEEE80211_NODE_VHTCAP |
        IEEE80211_NODE_VHT | IEEE80211_NODE_HE | IEEE80211_NODE_QOS;
    local.ni_chw = IEEE80211_CHAN_WIDTH_160;
    local.ni_htcaps = local.ni_htop0 = local.ni_vhtcaps = local.ni_vht_chanwidth = 0xff;
    memset(&local.ni_he_cap_elem, 0xff, sizeof(local.ni_he_cap_elem));
    memset(local.ni_basic_mcs, 0xff, sizeof(local.ni_basic_mcs));
    receive(response, true);
    assert(!local.ni_flags && local.ni_chw == IEEE80211_CHAN_WIDTH_20_NOHT &&
        !local.ni_htcaps && !local.ni_htop0 && !local.ni_vhtcaps && !local.ni_vht_chanwidth);
    for (auto byte : local.ni_he_cap_elem.phy_cap_info) assert(!byte);
    for (auto byte : local.ni_basic_mcs) assert(!byte);
    for (size_t size = 0; size < response.size(); ++size) {
        std::vector<uint8_t> truncated(response.begin(), response.begin() + size);
        receive(truncated, false);
    }
    for (uint8_t id : {uint8_t(IEEE80211_ELEMID_VHT_CAP), uint8_t(IEEE80211_ELEMID_VHT_OPMODE), uint8_t(IEEE80211_ELEMID_EXTENSION)}) {
        const size_t required = id == IEEE80211_ELEMID_VHT_CAP ? 12 :
                                id == IEEE80211_ELEMID_VHT_OPMODE ? 5 : 1;
        for (size_t length = 0; length < required; ++length) {
            auto shortIE = response;
            shortIE.push_back(id); shortIE.push_back(length);
            shortIE.resize(shortIE.size() + length);
            receive(shortIE, false);
        }
    }
    auto malformed = response; malformed.push_back(255); receive(malformed, false);
    malformed.push_back(2); malformed.push_back(35); receive(malformed, false);
    auto denied = response; denied[26] = IEEE80211_STATUS_UNSPECIFIED; receive(denied, false);
    assert(rejectedEvents == 1 && lastEvent.stage == ItlJoin::Stage::Assoc && lastEvent.status == IEEE80211_STATUS_UNSPECIFIED);
    auto zeroRates = response; zeroRates.resize(32); zeroRates[31] = 0; receive(zeroRates, false);
    auto appendIE = [](std::vector<uint8_t> &frame, uint8_t id, const std::vector<uint8_t> &bytes) {
        assert(bytes.size() <= 255);
        frame.push_back(id); frame.push_back(bytes.size());
        frame.insert(frame.end(), bytes.begin(), bytes.end());
    };
    for (unsigned length = 0; length < 256; ++length) {
        auto ht = response;
        appendIE(ht, IEEE80211_ELEMID_HTCAPS, std::vector<uint8_t>(length));
        appendIE(ht, IEEE80211_ELEMID_HTOP, std::vector<uint8_t>(22));
        memset(local.ni_basic_mcs, 0x5a, sizeof(local.ni_basic_mcs));
        receive(ht, length == 26);
        if (length == 26) for (auto byte : local.ni_basic_mcs) assert(byte == 0x5a);
        ht = response;
        appendIE(ht, IEEE80211_ELEMID_HTCAPS, std::vector<uint8_t>(26));
        appendIE(ht, IEEE80211_ELEMID_HTOP, std::vector<uint8_t>(length));
        receive(ht, length == 22);
    }
    std::vector<uint8_t> cap(1 + sizeof(ieee80211_he_cap_elem) + 4, 0), op(7, 0);
    cap[0] = IEEE80211_ELEMID_EXT_HE_CAPABILITY; op[0] = IEEE80211_ELEMID_EXT_HE_OPERATION;
    for (unsigned which = 0; which < 2; ++which) {
        const auto &ie = which ? op : cap;
        for (size_t length = 1; length <= ie.size(); ++length) {
            auto he = response;
            appendIE(he, IEEE80211_ELEMID_EXTENSION, which ? cap : std::vector<uint8_t>(ie.begin(), ie.begin() + length));
            appendIE(he, IEEE80211_ELEMID_EXTENSION, which ? std::vector<uint8_t>(ie.begin(), ie.begin() + length) : op);
            receive(he, length == ie.size());
        }
    }
    auto missingPair = response;
    appendIE(missingPair, IEEE80211_ELEMID_EXTENSION, cap); receive(missingPair, false);
    modeError = EINVAL; receive(response, false); modeError = 0;
    for (unsigned address : {10u, 16u}) {
        auto foreign = response; foreign[address] ^= 2;
        receive(foreign, false); assert(!rejectedEvents);
    }
    unsigned authCases = 0;
    for (unsigned state = 0; state <= IEEE80211_S_RUN; ++state)
        for (uint16_t seq : {uint16_t(0), uint16_t(1), uint16_t(2), uint16_t(3), uint16_t(65535)})
            for (uint16_t status : {uint16_t(0), uint16_t(1), uint16_t(17), uint16_t(65535)})
                for (unsigned identity = 0; identity < 4; ++identity) {
                    ieee80211_frame auth = {};
                    auth.i_fc[0] = IEEE80211_FC0_SUBTYPE_AUTH;
                    memcpy(auth.i_addr2, local.ni_bssid, 6); memcpy(auth.i_addr3, local.ni_bssid, 6);
                    if (identity == 1) auth.i_addr2[5] ^= 2;
                    if (identity == 2) auth.i_addr3[5] ^= 2;
                    ieee80211_node foreign = local;
                    queuedState = -1; authEvents = rejectedEvents = 0;
                    ic.ic_state = static_cast<ieee80211_state>(state);
                    ic.ic_flags = 0;
                    ieee80211_auth_open(&ic, &auth, identity == 3 ? &foreign : &local, &info, seq, status);
                    const bool valid = state == IEEE80211_S_AUTH && seq == 2 && !identity;
                    assert(authEvents == valid && rejectedEvents == (valid && status));
                    assert(queuedState == (valid && !status ? IEEE80211_S_ASSOC : -1));
                    if (valid) assert(lastEvent.status == status && lastEvent.stage == ItlJoin::Stage::Auth);
                    ++authCases;
                }
    printf("Actual BSD native authentication: %u state/sequence/status/peer combinations, exact owned events and no autonomous candidate retry passed\n", authCases);
    for (unsigned kind = 0; kind < 2; ++kind)
        for (unsigned state = 0; state <= IEEE80211_S_RUN; ++state)
            for (unsigned identity = 0; identity < 4; ++identity)
                for (unsigned length = 0; length <= 26; ++length) {
                    std::vector<uint8_t> frame(26, 0);
                    memcpy(frame.data() + 10, local.ni_bssid, 6);
                    memcpy(frame.data() + 16, local.ni_bssid, 6);
                    frame[24] = 0x34; frame[25] = 0x12;
                    if (identity == 1) frame[10] ^= 2;
                    if (identity == 2) frame[16] ^= 2;
                    frame.resize(length);
                    queuedState = -1; disconnectEvents = 0;
                    local.ni_port_valid = 1; linkState = LINK_STATE_UP; ic.ic_xflags = 0;
                    ic.ic_state = static_cast<ieee80211_state>(state);
                    auto foreign = local;
                    if (kind) ieee80211_recv_disassoc(&ic, &frame, identity == 3 ? &foreign : &local);
                    else ieee80211_recv_deauth(&ic, &frame, identity == 3 ? &foreign : &local);
                    const bool valid = state >= IEEE80211_S_AUTH && !identity && length == 26;
                    assert(disconnectEvents == valid && queuedState == -1 && local.ni_port_valid == !valid);
                    assert(linkState == (valid ? LINK_STATE_DOWN : LINK_STATE_UP));
                    assert(!!(ic.ic_xflags & IEEE80211_F_TX_MGMT_ONLY) == valid);
                    if (valid) assert(lastEvent.status == 0x1234 &&
                        lastEvent.stage == (kind ? ItlJoin::Stage::Disassoc : ItlJoin::Stage::Deauth));
                }
    puts("Actual native deauth/disassoc: 1080 exact-length/state/peer checks, immediate port close and no implicit retry passed");
    puts("Actual BSD association response: mandatory rates, exact frame truncations, short VHT/extension/trailing IEs and rejection status never emit success or queue RUN; PHY/hardware helpers mocked");
    puts("Association PHY refresh: stale HT/VHT/HE/width/QoS cleared, beacon basic MCS preserved for HT, 512 HT lengths and actual HE parser pairs checked; setmode failure never reports success");
}
