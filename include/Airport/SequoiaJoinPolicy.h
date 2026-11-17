#ifndef AIRPORT_ITLWM_SEQUOIA_JOIN_POLICY_H
#define AIRPORT_ITLWM_SEQUOIA_JOIN_POLICY_H

#include <Airport/SequoiaJoinRequest.h>
#include <Airport/apple80211_var.h>

namespace SequoiaWCL {

enum class JoinPolicyResult : uint8_t { Success, BadArgument, Unsupported };

// Bit positions are stable diagnostic field IDs, not firmware control bits.
// Report all unsupported fields in one attempt, without exposing credentials.
inline uint32_t unsupportedJoinControls(const JoinRequest &r)
{
    const bool rejected[] = {
        r.control00 != 0, r.wnmSupported > 1, r.apMode != 2 && r.apMode != 3,
        r.unassociatedDwell != 120, r.batterySaveMode != 0,
        r.controls1e0 != 0, r.controls1e4 != 2, r.controls1e8 != 0,
        !supportedJoinAllowAuths(r), r.controls3d0 != 0, r.controls3d4 != 20,
        r.controls3d8 != 5, r.extraIELength != 0, r.extraKeyLength != 0,
    };
    uint32_t mask = 0;
    for (unsigned i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i)
        if (rejected[i]) mask |= 1u << i;
    return mask;
}

// Initial explicit, single-candidate infrastructure join. fillAssocCandidatesList
// always supplies dwell 120, tail values 20/5 and default mode bit 2 at 0x1e4.
// Admit that baseline and audited RSN-PSK allow_auths; other opaque controls
// are not silently ignored.
// Security, beacon freshness, negotiated PHY and regulatory checks remain in HAL.
inline JoinPolicyResult validateJoinControls(const JoinRequestSnapshot &snapshot)
{
    const auto *request = snapshot.get();
    if (!request || !request->ssidLength || request->candidateCount != 1)
        return JoinPolicyResult::BadArgument;
    if (unsupportedJoinControls(*request))
        return JoinPolicyResult::Unsupported;
    // WNM is the candidate AP's advertised capability, not a requirement to
    // enable client WNM. This join does not advertise a new WNM capability.
    const uint8_t zero[6] = {};
    if (memcmp(request->mldAddress, zero, sizeof(zero))) return JoinPolicyResult::Unsupported;
    const auto &candidate = request->candidates[0];
    uint8_t any = 0;
    for (auto byte : candidate.bssid) any |= byte;
    if (!any || (candidate.bssid[0] & 1)) return JoinPolicyResult::BadArgument;
    // WCL marks a transition-mode AP as SAE-capable even when the selected
    // request is explicitly WPA2-PSK.  That flag describes an advertised
    // alternative, not the AKM chosen for this join.  Keep SAE-only and OWE
    // requests out of this WPA2-only path while allowing the usable PSK leg.
    const bool selectedWpa2Psk =
        request->authLower == APPLE80211_AUTHTYPE_OPEN &&
        request->authUpper == APPLE80211_AUTHTYPE_WPA2_PSK;
    if ((candidate.saePKCapable && !selectedWpa2Psk) ||
        memcmp(candidate.oweTransitionBssid, zero, sizeof(zero)))
        return JoinPolicyResult::Unsupported;
    if (memcmp(request->key.address, zero, sizeof(zero)) &&
        memcmp(request->key.address, candidate.bssid, sizeof(zero))) return JoinPolicyResult::BadArgument;
    if (request->reserved02[0] || request->reserved02[1] || request->reserved0e ||
        request->reserved1dd[0] || request->reserved1dd[1] || request->reserved1dd[2] ||
        request->reserved3cf || candidate.reserved01 || request->key.reserved62[0] ||
        request->key.reserved62[1]) return JoinPolicyResult::BadArgument;
    return JoinPolicyResult::Success;
}

} // namespace SequoiaWCL
#endif
