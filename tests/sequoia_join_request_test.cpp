#include <Airport/SequoiaJoinRequest.h>
#include <Airport/SequoiaJoinPolicy.h>
#include <assert.h>
#include <stdio.h>

using namespace SequoiaWCL;

int main()
{
    JoinRequest wire = {};
    wire.ssidLength = 32;
    wire.candidateCount = kMaxJoinCandidates;
    wire.key.length = 64;
    wire.key.rscLength = 8;
    wire.key.kckLength = wire.key.kekLength = 16;
    wire.extraKeyLength = 32;
    wire.rsnLength = wire.extraIELength = 257;
    for (unsigned i = 0; i < 32; ++i) wire.ssid[i] = i;
    memset(wire.key.bytes, 0xa5, sizeof(wire.key.bytes));
    for (unsigned i = 0; i < kMaxJoinCandidates; ++i) {
        wire.candidates[i].bssid[0] = 2;
        wire.candidates[i].bssid[5] = i;
        wire.candidates[i].channelSpec = 0x1001 + i;
    }
    JoinRequestSnapshot snapshot;
    assert(!snapshot.get());
    assert(snapshot.capture(&wire, sizeof(wire)));
    assert(memcmp(snapshot.get(), &wire, sizeof(wire)) == 0);
    wire.key.bytes[0] = 0;
    assert(snapshot.get()->key.bytes[0] == 0xa5);
    snapshot.clear();
    assert(!snapshot.get());

    uint8_t unaligned[sizeof(wire) + 8] = {};
    for (unsigned offset = 0; offset < 8; ++offset) {
        memcpy(unaligned + offset, &wire, sizeof(wire));
        assert(snapshot.capture(unaligned + offset, sizeof(wire)));
        assert(memcmp(snapshot.get(), &wire, sizeof(wire)) == 0);
    }
    for (size_t size = 0; size < sizeof(wire); ++size) {
        assert(!snapshot.capture(&wire, size));
        assert(!snapshot.get());
    }
    assert(!snapshot.capture(&wire, sizeof(wire) + 1));
    assert(!snapshot.capture(nullptr, sizeof(wire)));

    auto reject = [&](const JoinRequest &bad) {
        assert(snapshot.capture(&wire, sizeof(wire)));
        assert(!snapshot.capture(&bad, sizeof(bad)));
        assert(!snapshot.get());
    };
    const size_t offsets[] = {
        offsetof(JoinRequest, ssidLength), offsetof(JoinRequest, candidateCount),
        offsetof(JoinRequest, key) + offsetof(JoinKey, length),
        offsetof(JoinRequest, key) + offsetof(JoinKey, rscLength),
        offsetof(JoinRequest, key) + offsetof(JoinKey, kckLength),
        offsetof(JoinRequest, key) + offsetof(JoinKey, kekLength),
        offsetof(JoinRequest, extraKeyLength)
    };
    for (auto offset : offsets) {
        JoinRequest bad = wire;
        uint32_t length;
        auto *bytes = reinterpret_cast<uint8_t *>(&bad);
        memcpy(&length, bytes + offset, sizeof(length));
        ++length;
        memcpy(bytes + offset, &length, sizeof(length));
        reject(bad);
        length = UINT32_MAX;
        memcpy(bytes + offset, &length, sizeof(length));
        reject(bad);
    }
    JoinRequest bad = wire;
    bad.rsnLength = 258;
    reject(bad);
    bad = wire;
    bad.extraIELength = UINT16_MAX;
    reject(bad);
    assert(snapshot.capture(&wire, sizeof(wire)));
    assert(!snapshot.capture(snapshot.get(), sizeof(wire)));
    assert(!snapshot.get());

    uint8_t secret[128];
    memset(secret, 0xff, sizeof(secret));
    clearJoinSecret(secret, sizeof(secret));
    for (auto byte : secret) assert(!byte);
    wire = {};
    wire.ssidLength = 3; wire.ssid[0] = 'a'; wire.ssid[1] = 0; wire.ssid[2] = 'b';
    wire.candidateCount = 1; wire.candidates[0].bssid[0] = 2;
    wire.apMode = 2; wire.unassociatedDwell = 120;
    wire.controls1e4 = 2; wire.controls3d4 = 20; wire.controls3d8 = 5;
    for (unsigned fault = 0; fault < 30; ++fault) {
        auto candidate = wire;
        switch (fault) {
            case 0: break;
            case 1: candidate.control00 = 1; break;
            case 2: candidate.wnmSupported = 2; break;
            case 3: candidate.apMode = 1; break;
            case 4: candidate.unassociatedDwell = 121; break;
            case 5: candidate.batterySaveMode = 1; break;
            case 6: candidate.controls1e0 = 1; break;
            case 7: candidate.controls1e4 = 4; break;
            case 8: candidate.controls1e8 = 1; break;
            case 9: candidate.controls210 = 1; break;
            case 10: candidate.controls3d0 = 1; break;
            case 11: candidate.controls3d4 = 19; break;
            case 12: candidate.controls3d8 = 6; break;
            case 13: candidate.extraIELength = 1; break;
            case 14: candidate.extraKeyLength = 1; break;
            case 15: candidate.mldAddress[0] = 2; break;
            case 16: candidate.candidates[0].bssid[0] = 0; break;
            case 17: candidate.candidates[0].bssid[0] = 1; break;
            case 18: candidate.candidates[0].saePKCapable = 1; break;
            case 19: candidate.candidates[0].oweTransitionBssid[0] = 2; break;
            case 20: candidate.key.address[0] = 3; break;
            case 21: candidate.reserved02[1] = 1; break;
            case 22: candidate.reserved0e = 1; break;
            case 23: candidate.reserved1dd[2] = 1; break;
            case 24: candidate.reserved3cf = 1; break;
            case 25: candidate.candidates[0].reserved01 = 1; break;
            case 26: candidate.key.reserved62[1] = 1; break;
            case 27: candidate.candidateCount = 0; break;
            case 28: candidate.candidateCount = 2; break;
            case 29: candidate.ssidLength = 0; break;
        }
        assert(snapshot.capture(&candidate, sizeof(candidate)));
        if (fault >= 1 && fault <= 14)
            assert(unsupportedJoinControls(*snapshot.get()) == (1u << (fault - 1)));
        assert((validateJoinControls(snapshot) == JoinPolicyResult::Success) == (fault == 0));
    }
    auto restricted = wire;
    restricted.authLower = 1; restricted.authUpper = 8;
    restricted.controls210 = 4;
    assert(snapshot.capture(&restricted, sizeof(restricted)));
    assert(validateJoinControls(snapshot) == JoinPolicyResult::Success);
    // A transition AP may advertise SAE capability while WCL selected the
    // WPA2-PSK leg. The capability is an alternative, not a request for SAE.
    auto transition = restricted;
    transition.candidates[0].saePKCapable = 1;
    assert(snapshot.capture(&transition, sizeof(transition)));
    assert(validateJoinControls(snapshot) == JoinPolicyResult::Success);
    transition.authUpper = APPLE80211_AUTHTYPE_WPA3_SAE;
    assert(snapshot.capture(&transition, sizeof(transition)));
    assert(validateJoinControls(snapshot) == JoinPolicyResult::Unsupported);
    for (unsigned fault = 0; fault < 6; ++fault) {
        auto badAuth = restricted;
        switch (fault) {
            case 0: badAuth.authLower = 2; break;
            case 1: badAuth.authUpper = 0; break;
            case 2: badAuth.authUpper = 4; break;
            case 3: badAuth.authUpperExtended = 1; break;
            case 4: badAuth.controls210 |= 0x40000000; break;
            case 5: badAuth.controls210 = 0x100; break;
        }
        assert(snapshot.capture(&badAuth, sizeof(badAuth)));
        assert(unsupportedJoinControls(badAuth) == (1u << 8));
        assert(validateJoinControls(snapshot) == JoinPolicyResult::Unsupported);
    }
    auto multiple = wire;
    multiple.controls1e0 = 8;
    multiple.controls1e4 = 3;
    multiple.extraKeyLength = 32;
    assert(unsupportedJoinControls(multiple) == ((1u << 5) | (1u << 6) | (1u << 13)));
    wire.apMode = 3; wire.wnmSupported = 1;
    memcpy(wire.key.address, wire.candidates[0].bssid, 6);
    assert(snapshot.capture(&wire, sizeof(wire)));
    assert(validateJoinControls(snapshot) == JoinPolicyResult::Success);
    snapshot.clear();
    assert(validateJoinControls(snapshot) == JoinPolicyResult::BadArgument);
    puts("24G830 join request: owned/unaligned capture, length boundaries and secret clearing passed");
    puts("Native single-candidate baseline/RSN-PSK policy and opaque-control/peer cases passed; HAL security/channel validation still required");
}
