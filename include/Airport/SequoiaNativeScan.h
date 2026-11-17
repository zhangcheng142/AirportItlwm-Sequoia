#ifndef SEQUOIA_NATIVE_SCAN_H
#define SEQUOIA_NATIVE_SCAN_H

#include <Airport/SequoiaScanDelivery.h>
#include <Airport/SequoiaScanPlan.h>
#include <HAL/IwmScanTrial.h>
#include <HAL/ItlNativeScan.h>

namespace SequoiaWCL {

// Direct WCLBulletinBoard::sendMessage delivery, implemented in
// SequoiaPeerFactory.cpp and installed once from startNative. The scan delivery
// reaches it through a translation-unit pointer plus a setter rather than an
// extern object: native_lifecycle_sequoia.inc is included BEFORE
// native_scan_sequoia.inc, so a declaration at the install site would define a
// second, function-scope pointer and leave the one the delivery reads null
// (that is exactly what r223/d149 shipped: ItlwmNativeWclDirectPosts stayed 0).
using WclDirectPostRoute = bool (*)(void *interface, uint32_t msgId, void *bytes,
                                    size_t size, uint32_t *result);

// Owned request, bounded RX and result delivery shared by the native worker.
// Caller serializes every method on the actual IO80211/HAL workqueue.
class NativeScan {
public:
    // Bounded, read-only breadcrumbs for the real WCL scan path. These are
    // counters and status codes only; no SSID, BSSID or frame contents are
    // retained. The Airport layer mirrors them to the PCI provider so a
    // post-boot checker can distinguish request, transport and delivery
    // failures without another reboot for each hypothesis.
    struct Diagnostics {
        ItlScan::CacheDiagnostic cache;
        uint32_t requests = 0;
        uint32_t lastRequestResult = UINT32_MAX;
        uint32_t requestedChannels = 0;
        uint32_t requestActive = 0;
        uint32_t workerStarts = 0;
        uint32_t enableResult = UINT32_MAX;
        uint32_t nativeScanResult = UINT32_MAX;
        uint32_t submissions = 0;
        uint32_t lastSubmission = UINT32_MAX;
        uint32_t notifications = 0;
        uint32_t lastNotification = UINT32_MAX;
        uint32_t lastNotificationBytes = 0;
        uint32_t terminals = 0;
        uint32_t lastOutcome = UINT32_MAX;
        uint32_t beaconsQueued = 0;
        uint32_t beaconsRejected = 0;
        uint32_t deliveryResults = 0;
        uint32_t deliveryCompletions = 0;
        uint32_t deliveryRetries = 0;
        uint32_t deliveryNotReady = 0;
        uint32_t lastDelivery = UINT32_MAX;
        // Physical calls made to the interface's postMessage.  The logical
        // delivery counters above count one result even in the dual probe;
        // these counters show exactly which WCL route was handed to Apple's
        // interface and whether the 0xed completion was emitted.
        uint32_t wclResultPosts = 0;
        uint32_t wclFsmResultPosts = 0;
        uint32_t wclCacheResultPosts = 0;
        uint32_t wclCompletionPosts = 0;
        // The msgIndex actually handed to postMessage, encoded (msgId<<16)|msgType.
        // r221 encodes msgType 2; if a boot still shows the bare id (0xc9/0xce) the
        // encoding never reached the interface post call.
        uint32_t lastResultMsgIndex = UINT32_MAX;
        // r223 direct WCL board route (WCLBulletinBoard::sendMessage, bypassing the
        // pending-event queue whose last hop re-encodes a stale message). These show
        // how many deliveries took the direct route and what the board returned.
        uint32_t wclDirectPosts = 0;
        uint32_t wclDirectLastResult = UINT32_MAX;
        // WCLBulletinBoard::sendMessage returns the first non-zero handler result
        // (routeMsg accumulates it), and 0 both when every handler succeeded and
        // when sendMsgInWcl's bitmap mask was empty. A success therefore overwrites
        // lastResult, so a boot that cached some beacons and rejected others would
        // hide the rejection: retain the first failure code and count them too.
        uint32_t wclDirectFailures = 0;
        uint32_t wclDirectFirstFailure = UINT32_MAX;
        // r224: firmware-sequence markers (0x7d start / 0x7e complete) posted
        // around the result stream to drive the scan FSM into IN_PROGRESS.  These
        // test the hypothesis that the FSM state machine is dropping results
        // because no INFRA_SCAN_START was ever seen.  Off unless itlwm_scan_seq
        // selects the start/firmware route.
        uint32_t wclStartPosts = 0;
        uint32_t wclCompleteFirmwarePosts = 0;
        uint32_t wclStartLastResult = UINT32_MAX;
        uint32_t wclCompleteFirmwareLastResult = UINT32_MAX;
        bool scanSeqStarted = false;
        uint32_t legacyScanDone = 0;
        // Outer airportd scan completion route.  The native WCL completion is
        // still 0xed; this records only how the separate legacy message 10 was
        // sent so a boot can distinguish the audited interface path from the
        // controller path without retaining event payloads.
        uint32_t legacyCompletionRoute = UINT32_MAX;
        uint32_t legacyCompletionAttempts = 0;
        uint32_t legacyCompletionInterfacePosts = 0;
        uint32_t legacyCompletionControllerPosts = 0;
        // Request-frontier breadcrumbs. These distinguish a rejected channel
        // inventory/plan from a worker, HAL or firmware failure.
        uint32_t inventoryCount = 0;
        uint32_t inventoryLimit = 0;
        uint32_t rejectStage = UINT32_MAX;
        uint32_t rejectChannel = UINT32_MAX;
        uint32_t planResult = UINT32_MAX;
        // Controller/request shape at the WCL entry point. These values make
        // the INIT versus SCAN state distinction explicit without retaining
        // SSID, BSSID or frame contents.
        uint32_t controllerState = UINT32_MAX;
        uint32_t controllerHasBss = 0;
        uint32_t requestVersion = UINT32_MAX;
        uint32_t requestScanType = UINT32_MAX;
        uint32_t requestChannelCount = UINT32_MAX;
        uint32_t requestSsidCount = UINT32_MAX;
        uint32_t requestPrivateMac = UINT32_MAX;
        uint32_t requestScanFlags = UINT32_MAX;
        uint32_t requestHomeAwayTime = UINT32_MAX;
        uint32_t requestControl0c = UINT32_MAX;
        uint32_t requestBssType = UINT32_MAX;
        uint32_t requestActiveDwell = UINT32_MAX;
        uint32_t requestPassiveDwell = UINT32_MAX;
        uint32_t requestRestTime = UINT32_MAX;
        uint32_t requestShortSSID = UINT32_MAX;
        uint32_t requestShapeSequence = 0;
        uint32_t requestSsidLength = 0;
        uint32_t requestFirstChannel = UINT32_MAX;
        uint32_t requestFirstChannelFlags = 0;
        uint32_t planReason = 0;
        uint32_t planRejectCount = 0;
        uint32_t planRejectReasons = 0;
        uint32_t lastPlanFailureRequest = 0;
        ScanPlanDiagnostic lastPlanFailure;
        uint32_t acceptedRequest = 0;
        uint32_t probeChannels = 0;
        uint32_t passiveFallbacks = 0;
        uint32_t beaconsDecoded = 0;
        uint32_t beaconsDecodeRejected = 0;
        uint32_t beaconsFiltered = 0;
        // Dispatch-frontier breadcrumbs. CoreWLAN and airportd reach this
        // interface's apple80211 dispatcher through vtable slot +0xcc0, with the
        // selector in %esi: the family's apple80211getBGSCAN_CACHE_RESULTS wrapper
        // sends 0xd7 and apple80211getWCL_BGSCAN_CACHE_RESULT sends 0x1de, both
        // reading the scan cache CoreWLAN's network list comes from. An
        // unimplemented selector is otherwise silent - the family sees only a
        // non-zero IOReturn - and shows up as an empty network list, so record
        // which selectors were actually asked for, and whether the dispatcher
        // bailed out before it could answer because nativeAvailable() was false.
        uint32_t notReadyRequests = 0;
        uint32_t unsupportedRequests = 0;
        uint32_t lastUnsupportedSelector = UINT32_MAX;
        uint32_t unsupportedSelectors[4] = {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX};
        // WCL slot 583 carries one boolean. Intel firmware has no equivalent
        // roam-lock command, so the native adapter accepts only 0/1 and treats
        // the request as an advisory no-op. Keep the call/value/result visible
        // so a connection attempt can be correlated with the WCL preflight.
        uint32_t roamLockCalls = 0;
        uint32_t roamLockLastValue = UINT32_MAX;
        uint32_t roamLockLastResult = UINT32_MAX;
        // Configuration setters that used to be refused and are now accepted.
        // Kept separately from the unsupported record so a boot shows both what
        // is still missing and whether airportd's configuration sequence - the
        // one whose incompleteness shows up as EBUSY on its scans - now finishes.
        uint32_t configurationSetters = 0;
        uint32_t lastConfigurationSetter = UINT32_MAX;
        // r227: WCL capability selectors that were refused until now (the
        // r226 boot recorded 117 refusals of slots 495/521/524/575/585).
        // 495 getMAX_NSS_FOR_AP answers 8 bytes with the 1-stream value at
        // +4; 521 getWCL_TRAFFIC_COUNTERS and 524 getWCL_CHANNELS_INFO
        // answer audited fixed-size zero payloads; 575 setPM_MODE and 585
        // setWCL_ROAM_PROFILE_CONFIG are accepted as configuration setters.
        // itlwm_wcl_queries=off restores the old refusal so one build A/Bs.
        uint32_t wclQueryGate = 0;
        uint32_t wclQueryMaxNss = 0;
        uint32_t wclQueryTrafficCounters = 0;
        uint32_t wclQueryChannelsInfo = 0;
        uint32_t wclQueryHotChannels = 0;
        // WCL slot-530 cache reads.  A scan result can be delivered to the
        // family and still remain invisible if CoreWLAN cannot read the cache;
        // these counters distinguish that boundary without retaining SSIDs.
        uint32_t cacheRequests = 0;
        uint32_t cacheSuccesses = 0;
        uint32_t cacheNotReady = 0;
        uint32_t cacheLastResult = UINT32_MAX;
        uint32_t cacheLastCount = 0;
        uint32_t cacheLastValidEntries = 0;
        // r225 associated-scan mode (itlwm_assoc_scan boot-arg, off by
        // default).  The gate state and the per-scan disposition are published
        // so one boot distinguishes "gate off" from "gate on but the result
        // was unhealthy and withheld".  assocLastOutcome is 0 for a delivered
        // result set and otherwise the withhold reason (1 = fewer distinct
        // channels than min(3, channelCount), 2 = no non-AP channel evidence
        // on a multi-channel plan, 3 = fewer than 8 queued beacons).
        uint32_t assocScanEnabled = 0;
        uint32_t assocScans = 0;
        uint32_t assocApChannel = 0;
        uint32_t assocBeaconsQueued = 0;
        uint32_t assocBeaconChannels = 0;
        uint64_t assocBeaconChannelMask[4] = {};
        uint32_t assocWithheld = 0;
        uint32_t assocWithheldReason = UINT32_MAX;
        uint32_t assocLastOutcome = UINT32_MAX;
        // Q9 WCL scan-cache readback.  wclCacheCountBefore is the queue entry
        // count read at admission and wclCacheCountAfter the count read after
        // the delivery posted its completion, so a boot shows whether cached
        // entries persist across a scan without retaining SSIDs or BSSIDs.
        // The chain is scanManager+0x20 -> +0x68 -> +0x10 -> +0x00 (queue)
        // with the count at *(queue+0x10)+0x08, all verified against 24G830.
        uint32_t wclCacheCountBefore = 0;
        uint32_t wclCacheCountAfter = 0;
        uint32_t wclCacheReadError = 0;
        uint64_t wclCacheStorePtr = 0;
        uint64_t wclCacheQueuePtr = 0;
        // Result-shape breadcrumbs. These do not retain SSID/BSSID/frame
        // bytes; they only show whether the producer decoded a usable SSID
        // before the payload was handed to Apple's WCL receiver.
        uint32_t beaconsWithSSID = 0;
        uint32_t beaconsWithInformationElements = 0;
        uint32_t beaconsQueuedWithSSID = 0;
        uint32_t lastBeaconSSIDLength = 0;
        uint32_t lastBeaconIELength = 0;
        uint32_t lastBeaconChannel = UINT32_MAX;
        uint32_t lastBeaconFlags = 0x4000;
        uint32_t beaconsWithDS = 0;
        uint32_t beaconsWithDSBadLength = 0;
        uint32_t beaconsWithIBSS = 0;
        uint32_t beaconsWithIBSSBadLength = 0;
        uint32_t beaconsWithQBSS = 0;
        uint32_t beaconsWithQBSSBadLength = 0;
        uint32_t beaconsWithVHT = 0;
        uint32_t beaconsWithVHTBadLength = 0;
        uint32_t beaconsWithMalformedIE = 0;
        uint32_t lastBeaconIECount = 0;
        uint32_t lastBeaconFirstIE = UINT32_MAX;
        uint32_t lastBeaconSSIDIELength = 0;
        uint32_t lastBeaconDSLength = 0;
        uint32_t lastBeaconIBSSLength = 0;
        uint32_t lastBeaconQBSSLength = 0;
        uint32_t lastBeaconVHTLength = 0;
        // WCL route and glue-queue breadcrumbs.  These are deliberately kept
        // in the scan state so the host controller fixture and the kernel
        // provider publisher observe the same values.
        uint32_t resultRoute = UINT32_MAX;
        // Runtime debug overrides are changed only through the controller's
        // serialized property path. UINT32_MAX means the boot-argument value
        // remains in effect.
        uint32_t runtimeRoute = UINT32_MAX;
        uint32_t runtimeDoneRoute = UINT32_MAX;
        bool glueScheduleResult = false;
        bool glueScheduleObserved = false;
        uint64_t glueScheduleGate = 0;
        uint32_t glueWakeByteAfterSchedule = 0;
    } diagnostics;

    ScanPlan plan;
    ScanDelivery delivery;

    bool begin()
    {
        if (workerActive_ || delivery.busy() || !plan.valid()) return false;
        token_ = delivery.begin(ItlScan::Firmware::LMAC);
        if (!token_) return false;
        coverage_ = ItlScan::IwmPassiveTrial{};
        coverageToken_ = coverage_.begin(plan.channels, plan.channelCount);
        phy_ = {};
        memset(channelHits_, 0, sizeof(channelHits_));
        submitted_ = canceled_ = false;
        workerActive_ = true;
        diagnostics.scanSeqStarted = false;
        if (diagnostics.workerStarts != UINT32_MAX) ++diagnostics.workerStarts;
        diagnostics.requestedChannels = static_cast<uint32_t>(plan.channelCount);
        diagnostics.requestActive = plan.active() ? 1 : 0;
        diagnostics.acceptedRequest = diagnostics.requests;
        diagnostics.assocBeaconsQueued = 0;
        diagnostics.assocBeaconChannels = 0;
        for (unsigned i = 0; i < 4; ++i) diagnostics.assocBeaconChannelMask[i] = 0;
        diagnostics.assocApChannel = 0;
        diagnostics.assocLastOutcome = UINT32_MAX;
        if (plan.associatedScan()) {
            diagnostics.assocApChannel = plan.assocChannel();
            if (diagnostics.assocScans != UINT32_MAX) ++diagnostics.assocScans;
        }
        diagnostics.probeChannels = 0;
        for (size_t i = 0; i < plan.channelCount; ++i)
            if (plan.probes[i]) ++diagnostics.probeChannels;
        if (plan.passiveFallback && diagnostics.passiveFallbacks != UINT32_MAX)
            ++diagnostics.passiveFallbacks;
        return true;
    }

    void submitted(ItlScan::Submission result)
    {
        if (!workerActive_ || submitted_) return;
        submitted_ = true;
        if (diagnostics.submissions != UINT32_MAX) ++diagnostics.submissions;
        diagnostics.lastSubmission = static_cast<uint32_t>(result);
        coverage_.submitted(coverageToken_, result);
        delivery.submitted(token_, result);
    }

    void notification(uint16_t code, const void *payload, size_t size)
    {
        if (!workerActive_ || delivery.drained()) return;
        if (diagnostics.notifications != UINT32_MAX) ++diagnostics.notifications;
        diagnostics.lastNotification = code;
        diagnostics.lastNotificationBytes = size > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(size);
        if (code == 0xc0) {
            phy_ = {};
            if (ItlScan::decodeLegacyPhy(payload, size, phy_) != ItlScan::PhyDecode::Accepted) phy_ = {};
        } else if (code == 0xc1) {
            const auto *bytes = static_cast<const uint8_t *>(payload);
            if (!bytes || size < 8 || !phy_.channel) return;
            const size_t length = ItlScan::scanRead16(bytes);
            if (length > size - 8 || length < 36 || (bytes[4 + length] & 3) != 3) return;
            ItlScan::BeaconView beacon;
            if (ItlScan::decodeScanBeacon(bytes + 4, length, beacon)) {
                if (diagnostics.beaconsDecoded != UINT32_MAX) ++diagnostics.beaconsDecoded;
                // Channel evidence for the associated-scan health gate. Count
                // every decoded beacon, not just plan matches: a scan that only
                // hears the serving channel is exactly what r213 committed.
                if (phy_.channel <= kMaxChannelNumber && channelHits_[phy_.channel] != UINT8_MAX)
                    ++channelHits_[phy_.channel];
                const auto shape = inspectInformationElements(beacon.ies, beacon.ieLength);
                if (shape.ds && diagnostics.beaconsWithDS != UINT32_MAX) ++diagnostics.beaconsWithDS;
                if (shape.dsBadLength && diagnostics.beaconsWithDSBadLength != UINT32_MAX) ++diagnostics.beaconsWithDSBadLength;
                if (shape.ibss && diagnostics.beaconsWithIBSS != UINT32_MAX) ++diagnostics.beaconsWithIBSS;
                if (shape.ibssBadLength && diagnostics.beaconsWithIBSSBadLength != UINT32_MAX) ++diagnostics.beaconsWithIBSSBadLength;
                if (shape.qbss && diagnostics.beaconsWithQBSS != UINT32_MAX) ++diagnostics.beaconsWithQBSS;
                if (shape.qbssBadLength && diagnostics.beaconsWithQBSSBadLength != UINT32_MAX) ++diagnostics.beaconsWithQBSSBadLength;
                if (shape.vht && diagnostics.beaconsWithVHT != UINT32_MAX) ++diagnostics.beaconsWithVHT;
                if (shape.vhtBadLength && diagnostics.beaconsWithVHTBadLength != UINT32_MAX) ++diagnostics.beaconsWithVHTBadLength;
                if (shape.malformed && diagnostics.beaconsWithMalformedIE != UINT32_MAX) ++diagnostics.beaconsWithMalformedIE;
                diagnostics.lastBeaconSSIDLength = static_cast<uint32_t>(beacon.ssidLength);
                diagnostics.lastBeaconIELength = static_cast<uint32_t>(beacon.ieLength);
                diagnostics.lastBeaconChannel = phy_.channel;
                diagnostics.lastBeaconIECount = shape.total;
                diagnostics.lastBeaconFirstIE = shape.firstId;
                diagnostics.lastBeaconSSIDIELength = shape.ssidLength;
                diagnostics.lastBeaconDSLength = shape.dsLength;
                diagnostics.lastBeaconIBSSLength = shape.ibssLength;
                diagnostics.lastBeaconQBSSLength = shape.qbssLength;
                diagnostics.lastBeaconVHTLength = shape.vhtLength;
                if (beacon.ssidLength && diagnostics.beaconsWithSSID != UINT32_MAX)
                    ++diagnostics.beaconsWithSSID;
                if (beacon.ieLength && diagnostics.beaconsWithInformationElements != UINT32_MAX)
                    ++diagnostics.beaconsWithInformationElements;
                if (plan.matches(phy_, beacon)) {
                    const auto queued = delivery.queueBeacon(token_, phy_, bytes + 4, length);
                    recordBeacon(queued);
                    if (queued == ScanDelivery::Enqueue::Queued && beacon.ssidLength &&
                        diagnostics.beaconsQueuedWithSSID != UINT32_MAX)
                        ++diagnostics.beaconsQueuedWithSSID;
                }
                else if (diagnostics.beaconsFiltered != UINT32_MAX) ++diagnostics.beaconsFiltered;
            } else if (diagnostics.beaconsDecodeRejected != UINT32_MAX) {
                ++diagnostics.beaconsDecodeRejected;
            }
        } else if (code == 0xe7 || code == 0x6d) {
            if (coverage_.notification(code, payload, size)) {
                ItlScan::ScanNotification note;
                ItlScan::Outcome outcome;
                if (!ItlScan::decodeIwmNotification(static_cast<ItlScan::IwmNotification>(code), payload, size, note) ||
                    !ItlScan::terminalOutcome(note, outcome)) return;
                if (outcome == ItlScan::Outcome::Success && !coverage_.completeCoverage())
                    outcome = ItlScan::Outcome::TransportError;
                if (diagnostics.terminals != UINT32_MAX) ++diagnostics.terminals;
                diagnostics.lastOutcome = static_cast<uint32_t>(outcome);
                delivery.terminal(ItlScan::Firmware::LMAC, 0, outcome);
                phy_ = {};
            }
        }
    }

    bool cancel()
    {
        if (!workerActive_) return false;
        canceled_ = true;
        return delivery.cancel(token_);
    }
    bool canceled() const { return canceled_; }
    bool workerActive() const { return workerActive_; }

    void failed(ItlScan::Outcome outcome)
    {
        diagnostics.lastOutcome = static_cast<uint32_t>(outcome);
        if (outcome == ItlScan::Outcome::TimedOut) delivery.timeout(token_);
        else if (outcome == ItlScan::Outcome::Aborted) cancel();
        else delivery.transportFailed(token_);
    }

    // Called only after the HAL reset and RX-ring drain. Does not retire the
    // worker or its retained controller until the synchronous call returns.
    void hardwareStopped()
    {
        coverage_.hardwareStopped();
        delivery.hardwareStopped();
        phy_ = {};
    }

    void recordBeacon(ScanDelivery::Enqueue result)
    {
        if (result == ScanDelivery::Enqueue::Queued) {
            if (diagnostics.beaconsQueued != UINT32_MAX) ++diagnostics.beaconsQueued;
            if (plan.associatedScan() && diagnostics.assocBeaconsQueued != UINT32_MAX)
                ++diagnostics.assocBeaconsQueued;
        } else if (diagnostics.beaconsRejected != UINT32_MAX) {
            ++diagnostics.beaconsRejected;
        }
    }

    void recordDelivery(ScanDelivery::Delivery result)
    {
        diagnostics.lastDelivery = static_cast<uint32_t>(result);
        switch (result) {
            case ScanDelivery::Delivery::Result:
                if (diagnostics.deliveryResults != UINT32_MAX) ++diagnostics.deliveryResults;
                break;
            case ScanDelivery::Delivery::Complete:
                if (diagnostics.deliveryCompletions != UINT32_MAX) ++diagnostics.deliveryCompletions;
                break;
            case ScanDelivery::Delivery::Retry:
                if (diagnostics.deliveryRetries != UINT32_MAX) ++diagnostics.deliveryRetries;
                break;
            case ScanDelivery::Delivery::NotReady:
                if (diagnostics.deliveryNotReady != UINT32_MAX) ++diagnostics.deliveryNotReady;
                break;
            default:
                break;
        }
    }

    static void countPhysicalPost(uint32_t &counter)
    {
        if (counter != UINT32_MAX) ++counter;
    }

    void workerFinished()
    {
        if (!submitted_) submitted(ItlScan::Submission::NotSent);
        workerActive_ = false;
    }

    // Called once after the synchronous HAL scan returns and before the first
    // delivery pass can post the completion.  An associated scan running
    // bgscan-style sees mostly the serving AP's own beacons; committing that
    // set replaced the cached neighbour list on r213 and emptied the menu.
    // Withholding drops the queued beacons and forces the failed completion
    // that discards the WCL generation, leaving the previous cache intact.
    void finishAssociatedScan(bool requireDiversity = true)
    {
        if (!plan.associatedScan()) return;
        ItlScan::Completion completion;
        if (!delivery.completion(completion)) return;
        if (completion.outcome != ItlScan::Outcome::Success) return;
        uint32_t reason = 0;
        const bool healthy = assocScanHealthy(reason);
        // UMAC supplies per-channel completion coverage. A directed scan or a
        // quiet channel can legitimately yield fewer than eight beacons.
        // Keep the historical IWM diversity guard only for its opt-in path.
        diagnostics.assocLastOutcome = healthy || !requireDiversity ? 0 : reason;
        if (healthy || !requireDiversity) return;
        if (delivery.withhold()) {
            if (diagnostics.assocWithheld != UINT32_MAX) ++diagnostics.assocWithheld;
            diagnostics.assocWithheldReason = reason;
        }
    }

    // Audited 24G830 BCM generic scan failure, not an Intel errno or a claim
    // that Intel statuses have Broadcom firmware-specific meanings.
    static bool failureStatus(const ItlScan::Completion &, bool, uint32_t &status)
    {
        status = 0xe3ff8100;
        return true;
    }

private:
    // Plan inventory channels are capped at 196 (see ScanPlan::prepare), so a
    // direct-index histogram over the channel number is bounded and cheap.
    static constexpr uint16_t kMaxChannelNumber = 196;

    // The r225 health gate for associated scans.  reason is set to the first
    // failed criterion: 1 = fewer distinct channels than min(3, channelCount),
    // 2 = no non-AP channel evidence on a plan with 3+ channels,
    // 3 = fewer than 8 queued beacons.
    bool assocScanHealthy(uint32_t &reason)
    {
        reason = 0;
        uint32_t channelsSeen = 0;
        for (unsigned i = 1; i <= kMaxChannelNumber; ++i) {
            if (!channelHits_[i]) continue;
            ++channelsSeen;
            diagnostics.assocBeaconChannelMask[(i - 1) / 64] |= 1ull << ((i - 1) % 64);
        }
        diagnostics.assocBeaconChannels = channelsSeen;
        const uint32_t needed = plan.channelCount < 3 ? static_cast<uint32_t>(plan.channelCount) : 3;
        if (channelsSeen < needed) { reason = 1; return false; }
        if (plan.channelCount >= 3) {
            bool nonAp = false;
            for (unsigned i = 1; i <= kMaxChannelNumber; ++i)
                if (i != plan.assocChannel() && channelHits_[i]) { nonAp = true; break; }
            if (!nonAp) { reason = 2; return false; }
        }
        if (diagnostics.assocBeaconsQueued < 8) { reason = 3; return false; }
        return true;
    }

    ItlScan::IwmPassiveTrial coverage_;
    ItlScan::LegacyPhy phy_;
    uint8_t channelHits_[kMaxChannelNumber + 1] = {};
    uint64_t token_ = 0, coverageToken_ = 0;
    bool submitted_ = false, canceled_ = false, workerActive_ = false;
};
} // namespace SequoiaWCL
#endif
