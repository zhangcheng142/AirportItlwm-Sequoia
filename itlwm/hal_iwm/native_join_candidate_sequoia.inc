// Candidate preflight only: the join owner still validates all request controls,
// prepares security and checks negotiated rates before starting AUTH. This
// does not change the BSD state/configuration or authorize a WCL request.
// On success the caller owns one BSD reference, released under the HAL gate
// before detach. It must exclude new scans and recheck admission after sleeps;
// a reference prevents reclamation, not mutation of a cached beacon.
int ItlIwm::iwm_native_join_candidate(const SequoiaWCL::JoinRequestSnapshot &snapshot,
                                    size_t index, struct ieee80211_node **result)
{
    if (!result || *result) return EINVAL;
    if (!getMainWorkLoop()->inGate() || getMainWorkLoop()->onThread()) return EWOULDBLOCK;
    FirmwareLease operation(this);
    if (!operation) return EBUSY;
    nativeCandidateDiagnostic = {};
    auto *ic = &com.sc_ic;
    const auto *request = snapshot.get();
    if (!request || !request->ssidLength || index >= request->candidateCount) return EINVAL;
    if (isHardwareTrial() || !nativeNet80211Attached || nativeScanSink.valid() ||
        ic->ic_state != IEEE80211_S_INIT || ic->ic_opmode != IEEE80211_M_STA || !ic->ic_bss)
        return EBUSY;
    if (request->authLower != APPLE80211_AUTHTYPE_OPEN || request->authUpperExtended ||
        (request->authUpper && request->authUpper != APPLE80211_AUTHTYPE_WPA2_PSK))
        return EOPNOTSUPP;
    const auto &candidate = request->candidates[index];
    const uint8_t zero[6] = {};
    if (!ItlScan::validUnicast(candidate.bssid)) return EINVAL;
    // SAE capability can be advertised by a WPA2/WPA3 transition AP.  The
    // request still has to select WPA2-PSK; SAE-only remains unsupported.
    const bool selectedWpa2Psk =
        request->authLower == APPLE80211_AUTHTYPE_OPEN &&
        request->authUpper == APPLE80211_AUTHTYPE_WPA2_PSK;
    if ((candidate.saePKCapable && !selectedWpa2Psk) ||
        memcmp(candidate.oweTransitionBssid, zero, 6)) return EOPNOTSUPP;
    // WCL addAssocCandidates converts the advertised chanspec to primary
    // 20 MHz: preserved band bits 15:14, width 0x1000 and primary channel.
    // No 6 GHz, sideband, wide-channel or reserved encoding is inferred.
    const unsigned channel = candidate.channelSpec & 0xff;
    const unsigned band = candidate.channelSpec & 0xc000;
    if (!channel || channel >= nitems(ic->ic_channels) || channel > 196 ||
        (candidate.channelSpec & 0x3f00) != 0x1000 ||
        band != (channel <= 14 ? 0u : 0xc000u)) return EINVAL;
    auto *nvmChannel = &ic->ic_channels[channel];
    if (!isset(ic->ic_chan_avail, channel) || !nvmChannel->ic_freq ||
        (channel <= 14 ? !IEEE80211_IS_CHAN_2GHZ(nvmChannel) :
                         !IEEE80211_IS_CHAN_5GHZ(nvmChannel))) return ENODEV;
    auto *node = ieee80211_find_node(ic, candidate.bssid);
    const uint64_t now = airport_up_time();
    nativeCandidateDiagnostic = SequoiaWCL::inspectJoinCandidate(ic, node, nvmChannel,
        *request, index, now, IEEE80211_STA_CACHE);
    if (nativeCandidateDiagnostic.mask) return ENOENT;
    // Use the actual cached RSN, never the candidate's encryption hint.
    // Transition-mode APs may advertise additional suites, but this path
    // selects only WPA2/PSK/CCMP and must not negotiate required MFP.
    if (request->authUpper) {
        if (!(node->ni_capinfo & IEEE80211_CAPINFO_PRIVACY) || !node->ni_rsnie ||
            !(node->ni_rsnprotos & IEEE80211_PROTO_RSN) ||
            !(node->ni_rsnakms & IEEE80211_AKM_PSK) ||
            !(node->ni_rsnciphers & IEEE80211_CIPHER_CCMP) ||
            node->ni_rsngroupcipher != IEEE80211_CIPHER_CCMP ||
            (node->ni_rsncaps & IEEE80211_RSNCAP_MFPR)) return EOPNOTSUPP;
    } else if ((node->ni_capinfo & IEEE80211_CAPINFO_PRIVACY) ||
               node->ni_supported_rsnprotos) return EOPNOTSUPP;
    *result = ieee80211_ref_node(node);
    return 0;
}
