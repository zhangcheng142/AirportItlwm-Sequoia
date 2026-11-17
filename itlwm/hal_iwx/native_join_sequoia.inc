// Sequoia WCL join adapter for the IWX (AX200/AX210) firmware path.
// The BSD net80211 state machine still builds management frames and parses
// responses; this owner only supplies admission, serialization and cleanup.

int ItlIwx::iwx_native_join_candidate(const SequoiaWCL::JoinRequestSnapshot &snapshot,
                                       size_t index, struct ieee80211_node **result)
{
    if (!result || *result) return EINVAL;
    if (!getMainWorkLoop()->inGate() || getMainWorkLoop()->onThread()) return EWOULDBLOCK;
    FirmwareLease operation(this);
    if (!operation) return EBUSY;
    nativeCandidateDiagnostic = {};
    auto *ic = &com.sc_ic;
    const auto *request = snapshot.get();
    if (!request || !request->ssidLength || index >= request->candidateCount)
        return EINVAL;
    if (nativeDetached || !nativeNet80211Attached || nativeScanSink.valid() ||
        ic->ic_state != IEEE80211_S_INIT || ic->ic_opmode != IEEE80211_M_STA ||
        !ic->ic_bss)
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
        memcmp(candidate.oweTransitionBssid, zero, 6))
        return EOPNOTSUPP;

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

    if (request->authUpper) {
        if (!(node->ni_capinfo & IEEE80211_CAPINFO_PRIVACY) || !node->ni_rsnie ||
            !(node->ni_rsnprotos & IEEE80211_PROTO_RSN) ||
            !(node->ni_rsnakms & (IEEE80211_AKM_PSK | IEEE80211_AKM_SHA256_PSK)))
            return EOPNOTSUPP;
        SequoiaWCL::RsnSelection selection;
        if (!SequoiaWCL::selectedRsn(request->rsn, request->rsnLength, selection))
            return EOPNOTSUPP;
        const auto pair = selection.pairwise == 4 ? IEEE80211_CIPHER_CCMP : IEEE80211_CIPHER_TKIP;
        const auto group = selection.group == 4 ? IEEE80211_CIPHER_CCMP : IEEE80211_CIPHER_TKIP;
        const auto akm = selection.akm == 6 ? IEEE80211_AKM_SHA256_PSK : IEEE80211_AKM_PSK;
        if (!(node->ni_rsnciphers & pair) || node->ni_rsngroupcipher != group ||
            !(node->ni_rsnakms & akm)) return EOPNOTSUPP;
        // Do not downgrade a peer which offers CCMP to pairwise TKIP.
        if (pair == IEEE80211_CIPHER_TKIP && (node->ni_rsnciphers & IEEE80211_CIPHER_CCMP))
            return EOPNOTSUPP;
        if ((pair == IEEE80211_CIPHER_TKIP || group == IEEE80211_CIPHER_TKIP) &&
            ic->ic_native_tkip.active(airport_up_time())) return EBUSY;
        if ((node->ni_rsncaps & IEEE80211_RSNCAP_MFPR) && !selection.pmf)
            return EOPNOTSUPP;
        if (selection.pmf && (!(ic->ic_caps & IEEE80211_C_MFP) ||
            !(node->ni_rsncaps & IEEE80211_RSNCAP_MFPC) ||
            node->ni_rsngroupmgmtcipher != IEEE80211_CIPHER_BIP)) return EOPNOTSUPP;
    } else if ((node->ni_capinfo & IEEE80211_CAPINFO_PRIVACY) ||
               node->ni_supported_rsnprotos) return EOPNOTSUPP;
    *result = ieee80211_ref_node(node);
    return 0;
}

int ItlIwx::iwx_native_join_security(const SequoiaWCL::JoinRequestSnapshot &snapshot)
{
    if (!getMainWorkLoop()->inGate() || getMainWorkLoop()->onThread()) return EWOULDBLOCK;
    FirmwareLease operation(this);
    if (!operation) return EBUSY;
    auto *ic = &com.sc_ic;
    const auto *request = snapshot.get();
    if (!request || nativeDetached || !nativeNet80211Attached ||
        nativeScanSink.valid() || ic->ic_state != IEEE80211_S_INIT ||
        ic->ic_opmode != IEEE80211_M_STA || (ic->ic_flags & IEEE80211_F_WEPON))
        return EBUSY;
    for (size_t i = 0; i < nitems(ic->ic_nw_keys); ++i)
        if (ic->ic_nw_keys[i].k_cipher != IEEE80211_CIPHER_NONE) return EBUSY;
    if (!ic->ic_bss || ic->ic_bss->ni_pairwise_key.k_cipher != IEEE80211_CIPHER_NONE)
        return EBUSY;
    if (request->authLower != APPLE80211_AUTHTYPE_OPEN || request->authUpperExtended ||
        !SequoiaWCL::supportedJoinAllowAuths(*request))
        return EOPNOTSUPP;

    const auto &key = request->key;
    if (key.version > 1 || key.flags || key.index || key.rscLength || key.kckLength ||
        key.kekLength || request->extraKeyLength) return EOPNOTSUPP;
    const bool secured = request->authUpper == APPLE80211_AUTHTYPE_WPA2_PSK;
    ieee80211_wpaparams wpa = {};
    SequoiaWCL::RsnSelection selection;
    if (!request->authUpper) {
        if (key.length || key.cipher != APPLE80211_CIPHER_NONE || request->rsnLength)
            return EINVAL;
    } else if (secured) {
        if (!(ic->ic_caps & IEEE80211_C_RSN) || key.cipher != APPLE80211_CIPHER_PMK ||
            key.length != sizeof(ic->ic_psk)) return EOPNOTSUPP;
        if (!SequoiaWCL::selectedRsn(request->rsn, request->rsnLength, selection))
            return EOPNOTSUPP;
        if (selection.pmf && !(ic->ic_caps & IEEE80211_C_MFP)) return EOPNOTSUPP;
        if ((selection.pairwise == 2 || selection.group == 2) &&
            ic->ic_native_tkip.active(airport_up_time())) return EBUSY;
        wpa.i_enabled = 1;
        wpa.i_protos = IEEE80211_WPA_PROTO_WPA2;
        wpa.i_akms = selection.akm == 6 ? IEEE80211_WPA_AKM_SHA256_PSK : IEEE80211_WPA_AKM_PSK;
        wpa.i_ciphers = selection.pairwise == 4 ? IEEE80211_WPA_CIPHER_CCMP : IEEE80211_WPA_CIPHER_TKIP;
        wpa.i_groupcipher = selection.group == 4 ? IEEE80211_WPA_CIPHER_CCMP : IEEE80211_WPA_CIPHER_TKIP;
    } else return EOPNOTSUPP;

    if (secured) {
        const int error = ieee80211_ioctl_setwpaparms(ic, &wpa);
        if (error && error != ENETRESET) return error;
    } else ieee80211_disable_rsn(ic);
    ic->ic_native_pmf = secured && selection.pmf;
    ic->ic_flags &= ~IEEE80211_F_MFPR;
    if (secured && selection.requirePmf) ic->ic_flags |= IEEE80211_F_MFPR;
    SequoiaWCL::clearJoinSecret(ic->ic_psk, sizeof(ic->ic_psk));
    ic->ic_flags &= ~IEEE80211_F_PSK;
    if (secured) {
        memcpy(ic->ic_psk, key.bytes, sizeof(ic->ic_psk));
        ic->ic_flags |= IEEE80211_F_PSK;
    }
    return 0;
}

int ItlIwx::nativeJoinStart(const SequoiaWCL::JoinRequestSnapshot &snapshot, size_t index)
{
    if (!getMainWorkLoop()->inGate() || getMainWorkLoop()->onThread()) return EWOULDBLOCK;
    FirmwareLease operation(this);
    if (!operation) return EBUSY;
    auto *sc = &com;
    auto *ic = &sc->sc_ic;
    if (nativeError) return nativeError;
    if (nativeJoinProgress.active() || nativeJoinMode) return EBUSY;
    if (!nativeCommandTransport || !nativeNet80211Attached ||
        !(ic->ic_if.if_flags & IFF_RUNNING) || ic->ic_state != IEEE80211_S_INIT ||
        ic->ic_opmode != IEEE80211_M_STA ||
        (sc->sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR | IWX_FLAG_RFKILL)))
        return ENXIO;
    struct ieee80211_node *candidate = nullptr;
    int error = iwx_native_join_candidate(snapshot, index, &candidate);
    if (error) return error;
    const auto *request = snapshot.get();
    nativeCandidateDiagnostic.stage = 2;
    error = ieee80211_setmode(ic, IEEE80211_MODE_AUTO);
    if (!error) {
        nativeCandidateDiagnostic.stage = 3;
        error = iwx_native_join_security(snapshot);
    }
    if (!error) {
        ic->ic_des_esslen = request->ssidLength;
        bzero(ic->ic_des_essid, sizeof(ic->ic_des_essid));
        memcpy(ic->ic_des_essid, request->ssid, request->ssidLength);
        IEEE80211_ADDR_COPY(ic->ic_des_bssid, candidate->ni_bssid);
        ic->ic_des_chan = candidate->ni_chan;
        ic->ic_flags = (ic->ic_flags & ~(IEEE80211_F_AUTO_JOIN | IEEE80211_F_BGSCAN)) |
                       IEEE80211_F_DESBSSID;
        nativeCandidateDiagnostic.stage = 4;
        if (ieee80211_match_bss(ic, candidate, 0)) error = EINVAL;
        else {
            nativeCandidateDiagnostic.stage = 5;
            if (!nativeJoinProgress.begin(candidate->ni_bssid, sc->sc_generation)) error = EBUSY;
            else {
                nativeCandidateDiagnostic.stage = 6;
                nativeJoinMode = true;
                error = ieee80211_node_join_bss(ic, candidate, 0);
                if (!error) nativeCandidateDiagnostic.stage = 7;
            }
        }
        if (error) {
            nativeJoinProgress.clear();
            nativeJoinMode = false;
            ieee80211_disable_rsn(ic);
            SequoiaWCL::clearJoinSecret(ic->ic_psk, sizeof(ic->ic_psk));
            ic->ic_flags &= ~(IEEE80211_F_PSK | IEEE80211_F_DESBSSID);
            ic->ic_des_esslen = 0;
            bzero(ic->ic_des_essid, sizeof(ic->ic_des_essid));
            bzero(ic->ic_des_bssid, sizeof(ic->ic_des_bssid));
            ic->ic_des_chan = IEEE80211_CHAN_ANYC;
            ieee80211_node_newstate(candidate, IEEE80211_STA_CACHE);
        }
    }
    ieee80211_unref_node(&candidate);
    return error;
}

void ItlIwx::nativeJoinEvent(const ItlJoin::Event &event)
{
    if (!getMainWorkLoop()->inGate() || nativeDetached ||
        (com.sc_flags & IWX_FLAG_SHUTDOWN) ||
        !nativeJoinProgress.record(event, com.sc_generation)) return;
    if (nativeJoinProgress.failed() && !nativeError)
        nativeError = event.stage == ItlJoin::Stage::Deauth ||
                      event.stage == ItlJoin::Stage::Disassoc ? ENETDOWN : ECONNREFUSED;
    getMainCommandGate()->commandWakeup(&nativeStateCompleted, false);
}

void ItlIwx::iwx_native_newstate_task()
{
    auto *sc = &com;
    auto *ic = &sc->sc_ic;
    if (!getMainWorkLoop()->inGate() || getMainWorkLoop()->onThread() || nativeDetached ||
        (sc->sc_flags & IWX_FLAG_SHUTDOWN) || nativeError || !nativeJoinMode) return;
    const auto serial = nativeStateSerial;
    const int generation = sc->sc_generation;
    const auto requested = sc->ns_nstate;
    const auto previous = ic->ic_state;
    const int argument = sc->ns_arg;
    FirmwareLease operation(this);
    int error = operation ? 0 : EBUSY;
    auto current = [&]() {
        return !nativeDetached && generation == sc->sc_generation &&
            serial == nativeStateSerial && nativeCommandTransport &&
            !(sc->sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR | IWX_FLAG_RFKILL)) &&
            !nativeError;
    };
    if (!error && (!current() || !(ic->ic_if.if_flags & IFF_RUNNING) ||
        !ic->ic_bss || ic->ic_opmode != IEEE80211_M_STA)) error = ENXIO;
    if (!error && (requested < IEEE80211_S_INIT || requested > IEEE80211_S_RUN)) error = EINVAL;
    if (!error && requested == IEEE80211_S_SCAN) error = EOPNOTSUPP;
    if (!error && (previous == IEEE80211_S_SCAN ||
        (requested == IEEE80211_S_ASSOC && previous != IEEE80211_S_AUTH) ||
        (requested == IEEE80211_S_RUN && previous != IEEE80211_S_ASSOC))) error = EINVAL;
    if (!error && previous == IEEE80211_S_RUN) {
        iwx_del_task(sc, systq, &sc->ba_task);
        iwx_del_task(sc, systq, &sc->mac_ctxt_task);
        iwx_del_task(sc, systq, &sc->chan_ctxt_task);
        if (!current()) error = ECANCELED;
        else error = iwx_run_stop(sc);
    }
    if (!error && requested <= previous) {
        if (!current()) error = ECANCELED;
        else if (previous >= IEEE80211_S_AUTH && requested <= IEEE80211_S_AUTH)
            error = iwx_deauth(sc);
    }
    if (!error && !current()) error = ECANCELED;
    if (!error) {
        switch (requested) {
            case IEEE80211_S_AUTH: error = iwx_auth(sc); break;
            case IEEE80211_S_ASSOC: error = iwx_rs_init(sc, (struct iwx_node *)ic->ic_bss, false); break;
            case IEEE80211_S_RUN: error = iwx_run(sc); break;
            default: break;
        }
    }
    if (!error && !current()) error = ECANCELED;
    if (!error) error = sc->sc_newstate(ic, requested, argument);
    if (nativeDetached || generation != sc->sc_generation || (sc->sc_flags & IWX_FLAG_SHUTDOWN)) return;
    if (error && !nativeError) nativeError = error;
    nativeStateCompleted = serial;
    getMainCommandGate()->commandWakeup(&nativeStateCompleted, false);
}

int ItlIwx::nativeLeave(bool deauthenticate, uint16_t reason, unsigned waitMs)
{
    if (!getMainWorkLoop()->inGate() || getMainWorkLoop()->onThread()) return EWOULDBLOCK;
    if (!reason || waitMs > 1000) return EINVAL;
    FirmwareLease operation(this);
    if (!operation) return EBUSY;
    auto *ic = &com.sc_ic;
    if (ic->ic_state == IEEE80211_S_INIT) return 0;
    const auto generation = com.sc_generation;
    auto current = [&]() {
        return !nativeDetached && generation == com.sc_generation && nativeCommandTransport &&
            !nativeError && !(com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR | IWX_FLAG_RFKILL));
    };
    if (!current() || !(ic->ic_if.if_flags & IFF_RUNNING) || !ic->ic_bss ||
        !nativeJoinProgress.ownsPeer(ic->ic_bss->ni_bssid, generation)) return ENETDOWN;
    if (ic->ic_opmode != IEEE80211_M_STA || ic->ic_state < IEEE80211_S_AUTH) return EINVAL;
    if (!ic->ic_if.netStat || mq_full(&ic->ic_mgtq)) return ENOBUFS;
    const auto beforeErrors = ic->ic_if.netStat->outputErrors;
    const int error = ieee80211_send_mgmt(ic, ic->ic_bss,
        deauthenticate ? IEEE80211_FC0_SUBTYPE_DEAUTH : IEEE80211_FC0_SUBTYPE_DISASSOC,
        reason, 0);
    if (error) return error;
    const uint64_t started = airport_up_time();
    const unsigned budget = waitMs ? waitMs : 100;
    for (;;) {
        if (!current()) return ENETDOWN;
        if (ic->ic_if.netStat->outputErrors != beforeErrors) return EIO;
        bool pending = !mq_empty(&ic->ic_mgtq);
        for (unsigned qid = 0; qid < nitems(com.txq); ++qid)
            if (qid != IWX_DQA_CMD_QUEUE && com.txq[qid].queued) pending = true;
        if (!pending) return 0;
        const auto now = airport_up_time();
        if (now < started || now - started >= budget) return ETIMEDOUT;
        AbsoluteTime deadline;
        clock_interval_to_deadline(1, kMillisecondScale, &deadline);
        getMainCommandGate()->commandSleep(&com.txq, deadline, THREAD_UNINT);
        if (current()) iwx_start(&ic->ic_if);
    }
}

int ItlIwx::iwx_native_watchdog(uint64_t nowMs)
{
    if (!getMainWorkLoop()->inGate()) return EWOULDBLOCK;
    if (nativeError) return nativeError;
    auto *ic = &com.sc_ic;
    if (nativeDetached || !nativeNet80211Attached || !nativeCommandTransport || !ic->ic_bss ||
        !(ic->ic_if.if_flags & IFF_RUNNING) ||
        (com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR | IWX_FLAG_RFKILL)) ||
        !nativeJoinProgress.ownsPeer(ic->ic_bss->ni_bssid, com.sc_generation)) return ENETDOWN;
    // Accepted associated scans keep TX and peer probes running. Their
    // timers must run too; only exclusive non-data firmware phases pause them.
    if (nativeStateSerial != nativeStateCompleted || !iwx_native_data_operation_ready()) {
        nativeWatchdogActive = false;
        return 0;
    }
    if (!nativeWatchdogActive) {
        nativeWatchdogLastMs = nowMs;
        nativeWatchdogActive = true;
        return 0;
    }
    bool expired = nowMs < nativeWatchdogLastMs;
    if (!expired) {
        const uint64_t elapsedSeconds = (nowMs - nativeWatchdogLastMs) / 1000;
        if (!elapsedSeconds) return 0;
        nativeWatchdogLastMs += elapsedSeconds * 1000;
        if (com.sc_tx_timer > 0) {
            if (elapsedSeconds >= static_cast<uint64_t>(com.sc_tx_timer)) {
                com.sc_tx_timer = 0;
                expired = true;
            } else com.sc_tx_timer -= elapsedSeconds;
        }
        if (ic->ic_mgt_timer > 0) {
            if (elapsedSeconds >= static_cast<uint64_t>(ic->ic_mgt_timer)) {
                ic->ic_mgt_timer = 0;
                expired = true;
            } else ic->ic_mgt_timer -= elapsedSeconds;
        }
    }
    if (!expired) return 0;
    nativeError = ETIMEDOUT;
    ic->ic_bss->ni_port_valid = 0;
    ic->ic_if.if_link_state = LINK_STATE_DOWN;
    // Wake the scan worker so it can abort/drain its firmware lease before
    // the controller tears down the lost link. Never stop hardware here.
    cancelNativeScan();
    return nativeError;
}

bool ItlIwx::iwx_native_data_operation_ready() const
{
    // Firmware operations still cannot overlap. Only the accepted background
    // scan's sleep window permits ordinary data and software key processing;
    // both callers retain their gate, peer, RUN, transport and security checks.
    return !nativeFirmwareOwner.busy() ||
        (nativeScanDataAllowed && nativeScanDataGeneration == com.sc_generation &&
         nativeScanPlan && nativeScanPlan->associatedScan() && nativeScanSink.valid() &&
         !nativeScanCancel && nativeJoinMode &&
         !(com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR | IWX_FLAG_RFKILL)) &&
         (com.sc_flags & (IWX_FLAG_BGSCAN | IWX_FLAG_SCANNING)) == IWX_FLAG_BGSCAN);
}

int ItlIwx::iwx_native_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
                               struct ieee80211_key *k)
{
    if (!getMainWorkLoop()->inGate()) return EWOULDBLOCK;
    if (ic != &com.sc_ic || !ni || ni != ic->ic_bss || !k) return EINVAL;
    if (!nativeJoinMode) return iwx_set_key(ic, ni, k);
    if (nativeDetached || !nativeNet80211Attached || nativeError || !nativeCommandTransport ||
        (com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR | IWX_FLAG_RFKILL)) ||
        nativeStateSerial != nativeStateCompleted || !iwx_native_data_operation_ready() ||
        !(ic->ic_if.if_flags & IFF_RUNNING) || ic->ic_state != IEEE80211_S_RUN ||
        ic->ic_opmode != IEEE80211_M_STA ||
        !nativeJoinProgress.ownsPeer(ni->ni_bssid, com.sc_generation) ||
        !nativeJoinProgress.assoc() || nativeJoinProgress.assoc()->status)
        return ENETDOWN;
    if (!(ic->ic_flags & IEEE80211_F_RSNON) || !(ic->ic_flags & IEEE80211_F_PSK) ||
        ni->ni_rsnprotos != IEEE80211_PROTO_RSN ||
        (ni->ni_rsnakms != IEEE80211_AKM_PSK && ni->ni_rsnakms != IEEE80211_AKM_SHA256_PSK))
        return EOPNOTSUPP;
    if ((ni->ni_rsncipher == IEEE80211_CIPHER_TKIP ||
         ni->ni_rsngroupcipher == IEEE80211_CIPHER_TKIP) &&
        ic->ic_native_tkip.active(airport_up_time())) return ENETDOWN;
    if (k->k_priv) return EBUSY;
    if (k->k_flags == IEEE80211_KEY_IGTK) {
        if (!(ni->ni_flags & IEEE80211_NODE_MFP) ||
            ni->ni_rsncipher != IEEE80211_CIPHER_CCMP ||
            ni->ni_rsngroupcipher != IEEE80211_CIPHER_CCMP ||
            ni->ni_rsngroupmgmtcipher != IEEE80211_CIPHER_BIP ||
            k->k_cipher != IEEE80211_CIPHER_BIP || k->k_len != 16 ||
            (k->k_id != 4 && k->k_id != 5) || k != &ic->ic_nw_keys[k->k_id])
            return EOPNOTSUPP;
    } else {
        const auto cipher = (k->k_flags & IEEE80211_KEY_GROUP) ?
            ni->ni_rsngroupcipher : ni->ni_rsncipher;
        if ((cipher != IEEE80211_CIPHER_CCMP && cipher != IEEE80211_CIPHER_TKIP) ||
            k->k_cipher != cipher || k->k_len != (cipher == IEEE80211_CIPHER_TKIP ? 32 : 16) ||
            k->k_id > 3 || (k->k_flags & ~(IEEE80211_KEY_GROUP | IEEE80211_KEY_TX)))
            return EOPNOTSUPP;
        if (k->k_flags & IEEE80211_KEY_GROUP) {
            if (k != &ic->ic_nw_keys[k->k_id]) return EINVAL;
        } else if (k != &ni->ni_pairwise_key || k->k_id || k->k_flags) return EINVAL;
    }
    return ieee80211_set_key(ic, ni, k);
}

bool ItlIwx::iwx_native_port_ready()
{
    if (!getMainWorkLoop()->inGate() || nativeDetached || nativeError ||
        !nativeNet80211Attached || !nativeCommandTransport ||
        nativeStateSerial != nativeStateCompleted || !iwx_native_data_operation_ready() ||
        (com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR | IWX_FLAG_RFKILL))) return false;
    auto *ic = &com.sc_ic;
    auto *ni = ic->ic_bss;
    if (!ni || ic->ic_state != IEEE80211_S_RUN || ic->ic_opmode != IEEE80211_M_STA ||
        !(ic->ic_if.if_flags & IFF_RUNNING) || ic->ic_if.if_link_state != LINK_STATE_UP ||
        (ic->ic_flags & IEEE80211_F_WEPON) ||
        !nativeJoinProgress.ownsPeer(ni->ni_bssid, com.sc_generation) ||
        !nativeJoinProgress.assoc() || nativeJoinProgress.assoc()->status) return false;
    if (!(ic->ic_flags & IEEE80211_F_RSNON))
        return !(ic->ic_flags & IEEE80211_F_PSK) &&
            ni->ni_pairwise_key.k_cipher == IEEE80211_CIPHER_NONE;
    if (!(ic->ic_flags & IEEE80211_F_PSK) || !ni->ni_port_valid ||
        (ni->ni_flags & IEEE80211_NODE_TXRXPROT) != IEEE80211_NODE_TXRXPROT ||
        ni->ni_rsnprotos != IEEE80211_PROTO_RSN ||
        (ni->ni_rsnakms != IEEE80211_AKM_PSK && ni->ni_rsnakms != IEEE80211_AKM_SHA256_PSK))
        return false;
    if ((ni->ni_rsncipher != IEEE80211_CIPHER_CCMP && ni->ni_rsncipher != IEEE80211_CIPHER_TKIP) ||
        (ni->ni_rsngroupcipher != IEEE80211_CIPHER_CCMP && ni->ni_rsngroupcipher != IEEE80211_CIPHER_TKIP))
        return false;
    if ((ni->ni_rsncipher == IEEE80211_CIPHER_TKIP || ni->ni_rsngroupcipher == IEEE80211_CIPHER_TKIP) &&
        ic->ic_native_tkip.active(airport_up_time())) return false;
    const auto &pair = ni->ni_pairwise_key;
    if (pair.k_cipher != ni->ni_rsncipher ||
        pair.k_len != (pair.k_cipher == IEEE80211_CIPHER_TKIP ? 32 : 16) || pair.k_id ||
        pair.k_flags != IEEE80211_KEY_SWCRYPTO || !pair.k_priv) return false;
    if (ni->ni_flags & IEEE80211_NODE_MFP) {
        if (ni->ni_rsncipher != IEEE80211_CIPHER_CCMP || ni->ni_rsngroupcipher != IEEE80211_CIPHER_CCMP ||
            ni->ni_rsngroupmgmtcipher != IEEE80211_CIPHER_BIP ||
            (ni->ni_flags & (IEEE80211_NODE_TXMGMTPROT | IEEE80211_NODE_RXMGMTPROT)) != (IEEE80211_NODE_TXMGMTPROT | IEEE80211_NODE_RXMGMTPROT))
            return false;
        bool installed = false;
        for (unsigned id = 4; id <= 5; ++id) {
            const auto &key = ic->ic_nw_keys[id];
            installed |= key.k_cipher == IEEE80211_CIPHER_BIP && key.k_len == 16 &&
                key.k_id == id && key.k_flags == (IEEE80211_KEY_SWCRYPTO | IEEE80211_KEY_IGTK) && key.k_priv;
        }
        if (!installed) return false;
    }
    for (unsigned id = 0; id < 4; ++id) {
        const auto &group = ic->ic_nw_keys[id];
        if (group.k_cipher == ni->ni_rsngroupcipher &&
            group.k_len == (group.k_cipher == IEEE80211_CIPHER_TKIP ? 32 : 16) &&
            group.k_id == id &&
            (group.k_flags & ~IEEE80211_KEY_TX) ==
                (IEEE80211_KEY_SWCRYPTO | IEEE80211_KEY_GROUP) && group.k_priv)
            return true;
    }
    return false;
}

void ItlIwx::iwx_native_clear_keys()
{
    auto *ic = &com.sc_ic;
    for (auto &key : ic->ic_nw_keys) ieee80211_reset_key(ic, &key);
    if (ic->ic_bss) {
        auto *ni = ic->ic_bss;
        ieee80211_reset_key(ic, &ni->ni_pairwise_key);
        ni->ni_port_valid = 0;
        ni->ni_rsn_group_ack_pending = 0;
        explicit_bzero(ni->ni_rsn_group_ack_mic, sizeof(ni->ni_rsn_group_ack_mic));
        ni->ni_flags &= ~(IEEE80211_NODE_TXRXPROT | (IEEE80211_NODE_TXMGMTPROT | IEEE80211_NODE_RXMGMTPROT) |
                          IEEE80211_NODE_MFP | IEEE80211_NODE_PMK);
        explicit_bzero(&ni->ni_ptk, sizeof(ni->ni_ptk));
        explicit_bzero(ni->ni_pmk, sizeof(ni->ni_pmk));
        explicit_bzero(ni->ni_nonce, sizeof(ni->ni_nonce));
    }
    ic->ic_native_pmf = false;
    ic->ic_flags &= ~(IEEE80211_F_PSK | IEEE80211_F_MFPR);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    explicit_bzero(ic->ic_nonce, sizeof(ic->ic_nonce));
}

// Stop/re-enable is a repeated transaction on the same attached net80211
// instance.  Clear all firmware-owned software state, but retain the timer
// objects allocated during attach so a later native enable can re-arm them.
void ItlIwx::iwx_native_reset_runtime()
{
    nativeTxRateFlags = 0;
    nativeTxRateGeneration = -1;
    auto *sc = &com;
    auto *ic = &sc->sc_ic;
    auto *in = ic->ic_bss ? reinterpret_cast<struct iwx_node *>(ic->ic_bss) : nullptr;

    for (size_t i = 0; i < nitems(sc->sc_cmd_resp_pkt); ++i) {
        ::free(sc->sc_cmd_resp_pkt[i]);
        sc->sc_cmd_resp_pkt[i] = nullptr;
        sc->sc_cmd_resp_len[i] = 0;
    }
    memset(sc->sc_tid_data, 0, sizeof(sc->sc_tid_data));
    for (size_t i = 0; i < nitems(sc->sc_tid_data); ++i)
        sc->sc_tid_data[i].qid = IWX_INVALID_QUEUE;

    sc->sc_rx_ba_sessions = 0;
    sc->ba_rx.start_tidmask = 0;
    sc->ba_rx.stop_tidmask = 0;
    sc->ba_tx.start_tidmask = 0;
    sc->ba_tx.stop_tidmask = 0;
    sc->sc_ampdu_ref = 0;
    sc->sc_time_event_uid = 0;
    memset(&sc->sc_last_phy_info, 0, sizeof(sc->sc_last_phy_info));
    sc->sc_last_phy_info.cfg_phy_cnt = 0xff;

    if (in) {
        in->in_phyctxt = nullptr;
        in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
        IEEE80211_ADDR_COPY(in->in_macaddr, etheranyaddr);
    }

    for (size_t i = 0; i < nitems(sc->sc_rxba_data); ++i) {
        auto *rxba = &sc->sc_rxba_data[i];
        if (rxba->session_timer) timeout_del(&rxba->session_timer);
        if (rxba->reorder_buf.reorder_timer) timeout_del(&rxba->reorder_buf.reorder_timer);
        for (size_t j = 0; j < nitems(rxba->entries); ++j) {
            ml_purge(&rxba->entries[j].frames);
            timerclear(&rxba->entries[j].reorder_time);
            rxba->entries[j].rx_pkt_status = 0;
            rxba->entries[j].chanidx = 0;
            rxba->entries[j].is_shortpre = 0;
            rxba->entries[j].rate_n_flags = 0;
            rxba->entries[j].device_timestamp = 0;
            memset(&rxba->entries[j].rxi, 0, sizeof(rxba->entries[j].rxi));
        }
        rxba->sta_id = 0;
        rxba->tid = 0;
        rxba->timeout = 0;
        rxba->entries_per_queue = 0;
        timerclear(&rxba->last_rx);
        rxba->reorder_buf.head_sn = 0;
        rxba->reorder_buf.num_stored = 0;
        rxba->reorder_buf.buf_size = 0;
        rxba->reorder_buf.last_amsdu = 0;
        rxba->reorder_buf.last_sub_index = 0;
        rxba->reorder_buf.removed = 1;
        rxba->reorder_buf.valid = 0;
        rxba->reorder_buf.consec_oldsn_drops = 0;
        rxba->reorder_buf.consec_oldsn_ampdu_gp2 = 0;
        rxba->reorder_buf.consec_oldsn_prev_drop = 0;
        rxba->baid = IWX_RX_REORDER_DATA_INVALID_BAID;
    }
}

int ItlIwx::iwx_native_stop()
{
    if (!getMainWorkLoop()->inGate() || getMainWorkLoop()->onThread()) return EWOULDBLOCK;
    FirmwareLease operation(this);
    if (!operation) return EBUSY;
    auto *sc = &com;
    auto *ic = &sc->sc_ic;
    auto *ifp = &ic->ic_if;
    if (sc->sc_flags & IWX_FLAG_SHUTDOWN) return 0;
    sc->sc_flags |= IWX_FLAG_SHUTDOWN;
    nativeCommandTransport = false;
    ++sc->sc_generation;
    task_del(systq, &sc->init_task);
    if (!taskq_is_current(systq, &sc->init_task))
        taskq_del_barrier(systq, &sc->init_task);
    if (sc->sc_nswq) taskq_del_barrier(sc->sc_nswq, &sc->newstate_task);
    taskq_del_barrier(systq, &sc->ba_task);
    taskq_del_barrier(systq, &sc->mac_ctxt_task);
    taskq_del_barrier(systq, &sc->chan_ctxt_task);
    iwx_stop_device(sc);
    ifp->if_flags &= ~IFF_RUNNING;
    ifq_clr_oactive(&ifp->if_snd);
    ifq_flush(&ifp->if_snd);
    sc->sc_flags &= ~(IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN | IWX_FLAG_MAC_ACTIVE |
                      IWX_FLAG_BINDING_ACTIVE | IWX_FLAG_STA_ACTIVE | IWX_FLAG_TE_ACTIVE |
                      IWX_FLAG_HW_ERR | IWX_FLAG_TXFLUSH | IWX_FLAG_SHUTDOWN);
    if (sc->sc_newstate && ic->ic_state != IEEE80211_S_INIT)
        sc->sc_newstate(ic, IEEE80211_S_INIT, -1);
    sc->ns_nstate = IEEE80211_S_INIT;
    nativeJoinProgress.clear();
    nativeJoinMode = false;
    nativeStateCompleted = nativeStateSerial;
    nativeWatchdogActive = false;
    nativeWatchdogLastMs = 0;
    iwx_native_clear_keys();
    iwx_native_reset_runtime();
    nativeError = 0;
    ifp->if_timer = sc->sc_tx_timer = 0;
    return 0;
}
