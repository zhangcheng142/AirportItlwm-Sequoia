// Associated scanning defaults to the HAL capability. IWX supports UMAC
// background scans; the older IWM experiment still requires itlwm_assoc_scan=1.  The gate exists because r213 admitted associated
// requests unconditionally and the resulting AP-only scan replaced the cached
// neighbour list, which is what this mode's health gate prevents.
// requestNativeScan reads it long before the anonymous-namespace route block
// further down, so the atomic and accessors live here at file scope.
static uint32_t gNativeAssocScanOverride = UINT32_MAX;

static uint32_t nativeAssocScanOverride()
{
    return __atomic_load_n(&gNativeAssocScanOverride, __ATOMIC_ACQUIRE);
}

static void setNativeAssocScanOverride(uint32_t value)
{
    __atomic_store_n(&gNativeAssocScanOverride, value, __ATOMIC_RELEASE);
}

static bool nativeAssocScanEnabled(bool supported = false)
{
    const uint32_t override = nativeAssocScanOverride();
    if (override <= 1) return override != 0;
    char value[8] = {};
    // r226: PE_parse_boot_argn stores NUMERIC values ("1") as a binary integer
    // in the buffer, so strcmp(value, "1") could never match; only non-numeric
    // values reach the string form.  PE_parse_boot_arg_str always copies the
    // value as a NUL-terminated string (verified against the 24G830 KDK
    // _PE_parse_boot_argn_internal disassembly).
    if (!PE_parse_boot_arg_str("itlwm_assoc_scan", value, sizeof(value))) return supported;
    return !strcmp(value, "1") || !strcmp(value, "on");
}

// r227: WCL capability-query acceptance is on by default; itlwm_wcl_queries=off
// restores the pre-r227 refusal so a single build can A/B whether these
// refusals are what empties the Settings list.
static uint32_t gNativeWclQueriesOverride = UINT32_MAX;

static uint32_t nativeWclQueriesOverride()
{
    return __atomic_load_n(&gNativeWclQueriesOverride, __ATOMIC_ACQUIRE);
}

static void setNativeWclQueriesOverride(uint32_t value)
{
    __atomic_store_n(&gNativeWclQueriesOverride, value, __ATOMIC_RELEASE);
}

static bool nativeWclQueriesGateEnabled()
{
    const uint32_t override = nativeWclQueriesOverride();
    if (override <= 1) return override != 0;
    char value[8] = {};
    // Same string-parser form as the r226 assoc gate; PE_parse_boot_argn
    // stores numeric values as binary integers and would hide "0"/"off".
    if (!PE_parse_boot_arg_str("itlwm_wcl_queries", value, sizeof(value))) return true;
    return strcmp(value, "off") && strcmp(value, "0");
}

bool AirportItlwm::nativeWclQueriesEnabled()
{
    return nativeWclQueriesGateEnabled();
}

void AirportItlwm::recordWclQuery(uint32_t selector)
{
    auto &d = nativeScan.diagnostics;
    switch (selector) {
        case 495: if (d.wclQueryMaxNss != UINT32_MAX) ++d.wclQueryMaxNss; break;
        case 521: if (d.wclQueryTrafficCounters != UINT32_MAX) ++d.wclQueryTrafficCounters; break;
        case 524: if (d.wclQueryChannelsInfo != UINT32_MAX) ++d.wclQueryChannelsInfo; break;
        case 518: if (d.wclQueryHotChannels != UINT32_MAX) ++d.wclQueryHotChannels; break;
        default: return;
    }
    publishNativeScanDiagnostics();
}

// Implemented in SequoiaPeerFactory.cpp: walk the verified 24G830 WCL
// scan-cache chain (scanManager+0x20 -> +0x68 -> +0x10 -> +0x00) and read the
// IO80211Queue entry count at *(queue+0x10)+0x08.  Only counters and pointers
// are returned; no SSID, BSSID or frame contents are retained.
bool itlwmReadWclCacheQueueCount(void *interface, uint64_t *count, void **cacheStore, void **queue);

bool AirportItlwm::initNativeScan()
{
    using Delivery = SequoiaWCL::ScanDelivery;
    nativeScanStorage = static_cast<Delivery::Slot *>(IOMalloc(sizeof(Delivery::Slot) * Delivery::MaxSlots));
    if (!nativeScanStorage) return false;
    if (!nativeScan.delivery.setStorage(nativeScanStorage, Delivery::MaxSlots)) {
        IOFree(nativeScanStorage, sizeof(Delivery::Slot) * Delivery::MaxSlots);
        nativeScanStorage = nullptr;
        return false;
    }
    nativeScanCall = SequoiaThreadCall::allocate(nativeScanWorker, this);
    if (!nativeScanCall) return false;
    nativeScanPostCall = SequoiaThreadCall::allocate(nativeScanPostWorker, this);
    if (!nativeScanPostCall) {
        SequoiaThreadCall::destroy(nativeScanCall);
        nativeScan.delivery.releaseStorage();
        IOFree(nativeScanStorage, sizeof(Delivery::Slot) * Delivery::MaxSlots);
        nativeScanStorage = nullptr;
        return false;
    }
    nativeScanTimer = IOTimerEventSource::timerEventSource(this, nativeScanTimerAction);
    if (!nativeScanTimer || _fWorkloop->addEventSource(nativeScanTimer) != kIOReturnSuccess) {
        OSSafeReleaseNULL(nativeScanTimer);
        SequoiaThreadCall::destroy(nativeScanPostCall);
        SequoiaThreadCall::destroy(nativeScanCall);
        nativeScan.delivery.releaseStorage();
        IOFree(nativeScanStorage, sizeof(Delivery::Slot) * Delivery::MaxSlots);
        nativeScanStorage = nullptr;
        return false;
    }
    nativeScanTimerAdded = true;
    nativeScan.diagnostics.wclQueryGate = nativeWclQueriesEnabled() ? 1u : 0u;
    return true;
}

IOReturn AirportItlwm::requestNativeScan(void *data)
{
    using namespace SequoiaWCL;
    // Values are intentionally numeric and stable in the post-boot report:
    // 0=radio, 1=busy, 2=argument, 3=controller, 4=inventory-overflow,
    // 5=channel-encoding, 6=plan, 7=begin, 8=timer, 9=threadcall,
    // 10=association-state.
    enum : uint32_t {
        RejectRadio = 0, RejectBusy = 1, RejectArgument = 2,
        RejectController = 3, RejectInventoryOverflow = 4,
        RejectChannelEncoding = 5, RejectPlan = 6, RejectBegin = 7,
        RejectTimer = 8, RejectThreadcall = 9, RejectAssociationState = 10
    };
    if (nativeScan.diagnostics.requests != UINT32_MAX) ++nativeScan.diagnostics.requests;
    nativeScan.diagnostics.inventoryCount = 0;
    nativeScan.diagnostics.inventoryLimit = ScanPlan::MaxChannels;
    nativeScan.diagnostics.rejectStage = UINT32_MAX;
    nativeScan.diagnostics.rejectChannel = UINT32_MAX;
    nativeScan.diagnostics.planResult = UINT32_MAX;
    nativeScan.diagnostics.planReason = UINT32_MAX;
    auto finishRequest = [this](IOReturn result) {
        nativeScan.diagnostics.lastRequestResult = static_cast<uint32_t>(result);
        publishNativeScanDiagnostics();
        return result;
    };
    if (!nativeRadioAvailable() || !nativeScanCall || !nativeScanTimerAdded || !power_state) {
        nativeScan.diagnostics.rejectStage = RejectRadio;
        return finishRequest(kIOReturnNotReady);
    }
    // nativeJoin.busy stays true for the whole of a connected session: serviceNativeJoin
    // sets connected=true on success but never clears busy, because the leave/link
    // paths use busy to mean "there is an active association to tear down". A scan
    // must still be admitted while connected (the r210 boot proved it: JoinConnected=1
    // yet every post-join scan was refused with RejectStage=RejectBusy, driving 49 of
    // 51 SCAN_REQ_FAILED and leaving the WCL cache - and thus the Settings list - empty).
    // Refuse only a join that is still in flight, never an established connection.
    if ((nativeJoin.busy && !nativeJoin.connected) || nativeScan.workerActive() ||
        nativeScan.delivery.busy() ||
        __atomic_load_n(&nativeScanPostMask, __ATOMIC_ACQUIRE)) {
        nativeScan.diagnostics.rejectStage = RejectBusy;
        return finishRequest(kIOReturnBusy);
    }
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    if (!hal || !data) {
        nativeScan.diagnostics.rejectStage = RejectArgument;
        return finishRequest(kIOReturnBadArgument);
    }
    auto *ic = hal->nativeController();
    if (!ic) {
        nativeScan.diagnostics.rejectStage = RejectController;
        return finishRequest(kIOReturnNotReady);
    }
    nativeScan.diagnostics.controllerState = static_cast<uint32_t>(ic->ic_state);
    nativeScan.diagnostics.controllerHasBss = ic->ic_bss ? 1u : 0u;
    {
        nativeScan.diagnostics.requestShapeSequence = nativeScan.diagnostics.requests;
        const auto *raw = static_cast<const uint8_t *>(data);
        auto read32 = [raw](size_t offset) {
            uint32_t value = 0;
            memcpy(&value, raw + offset, sizeof(value));
            return value;
        };
        nativeScan.diagnostics.requestVersion = read32(offsetof(ScanRequest, version));
        nativeScan.diagnostics.requestScanType = read32(offsetof(ScanRequest, scanType));
        nativeScan.diagnostics.requestChannelCount = read32(offsetof(ScanRequest, channelCount));
        nativeScan.diagnostics.requestSsidCount = read32(offsetof(ScanRequest, ssidCount));
        nativeScan.diagnostics.requestPrivateMac = static_cast<uint32_t>(raw[offsetof(ScanRequest, privateMAC)]);
        uint16_t scanFlags = 0;
        memcpy(&scanFlags, raw + offsetof(ScanRequest, scanFlags), sizeof(scanFlags));
        nativeScan.diagnostics.requestScanFlags = scanFlags;
        nativeScan.diagnostics.requestHomeAwayTime = read32(offsetof(ScanRequest, homeAwayTime));
        nativeScan.diagnostics.requestControl0c = read32(offsetof(ScanRequest, control0c));
        nativeScan.diagnostics.requestBssType = read32(offsetof(ScanRequest, bssType));
        nativeScan.diagnostics.requestActiveDwell = read32(offsetof(ScanRequest, activeDwell));
        nativeScan.diagnostics.requestPassiveDwell = read32(offsetof(ScanRequest, passiveDwell));
        nativeScan.diagnostics.requestRestTime = read32(offsetof(ScanRequest, restTime));
        nativeScan.diagnostics.requestShortSSID = read32(offsetof(ScanRequest, shortSSID));
        nativeScan.diagnostics.requestSsidLength = read32(offsetof(ScanRequest, ssidLength));
        nativeScan.diagnostics.requestFirstChannel = UINT32_MAX;
        nativeScan.diagnostics.requestFirstChannelFlags = 0;
        if (nativeScan.diagnostics.requestChannelCount > 0 &&
            nativeScan.diagnostics.requestChannelCount <= kMaxSupportedChannels) {
            nativeScan.diagnostics.requestFirstChannel = read32(offsetof(ScanRequest, channels) + offsetof(Channel, number));
            nativeScan.diagnostics.requestFirstChannelFlags = read32(offsetof(ScanRequest, channels) + offsetof(Channel, flags));
        }
    }
    // INIT and SCAN are both unassociated states. AUTH/ASSOC are transitional
    // join states and must not race a new scan. RUN is associated only when a
    // current BSS exists; the former `state != INIT` test rejected every
    // normal unassociated scan after net80211 entered IEEE80211_S_SCAN.
    if (ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC) {
        nativeScan.diagnostics.rejectStage = RejectAssociationState;
        return finishRequest(kIOReturnBusy);
    }
    const bool associated = ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != nullptr;
    // The HAL capability supplies the default; the boot argument can override it.
    // The plan still rejects when the caller passes `associated` true, so it
    // receives `associated && !admitAssociated`: unassociated requests always
    // proceed, gated associated requests get the bgscan-style plan below.
    const bool admitAssociated = associated && nativeAssocScanEnabled(hal->nativeAssociatedScanSupported());
    nativeScan.diagnostics.assocScanEnabled = admitAssociated ? 1u : 0u;
    Channel inventory[ScanPlan::MaxChannels];
    size_t count = 0;
    for (unsigned i = 1; i <= IEEE80211_CHAN_MAX; ++i) {
        const auto &channel = ic->ic_channels[i];
        if (!channel.ic_freq || !isset(ic->ic_chan_avail, i)) continue;
        const bool band2 = IEEE80211_IS_CHAN_2GHZ(&channel);
        const bool band5 = IEEE80211_IS_CHAN_5GHZ(&channel);
        if (band2 == band5) {
            nativeScan.diagnostics.rejectStage = RejectChannelEncoding;
            nativeScan.diagnostics.rejectChannel = i;
            return finishRequest(kIOReturnUnsupported);
        }
        if (count == ARRAY_SIZE(inventory)) {
            nativeScan.diagnostics.inventoryCount = static_cast<uint32_t>(count + 1);
            nativeScan.diagnostics.rejectStage = RejectInventoryOverflow;
            nativeScan.diagnostics.rejectChannel = i;
            return finishRequest(kIOReturnUnsupported);
        }
        if (!channel20MHz(i, band2 ? Band::GHz2 : Band::GHz5,
            channel.ic_flags & IEEE80211_CHAN_PASSIVE, channel.ic_flags & IEEE80211_CHAN_DFS,
            inventory[count])) {
            nativeScan.diagnostics.rejectStage = RejectChannelEncoding;
            nativeScan.diagnostics.rejectChannel = i;
            return finishRequest(kIOReturnUnsupported);
        }
        ++count;
    }
    nativeScan.diagnostics.inventoryCount = static_cast<uint32_t>(count);
    uint8_t entropy[6];
    arc4random_buf(entropy, sizeof(entropy));
    const auto result = nativeScan.plan.prepare(data, sizeof(ScanRequest), inventory, count,
        ic->ic_myaddr, entropy, sizeof(entropy), associated && !admitAssociated);
    memset(entropy, 0, sizeof(entropy));
    nativeScan.diagnostics.planResult = static_cast<uint32_t>(result);
    nativeScan.diagnostics.planReason = static_cast<uint32_t>(nativeScan.plan.diagnostic.reason);
    if (result != ScanPlanStatus::Success) {
        auto &d = nativeScan.diagnostics;
        if (d.planRejectCount != UINT32_MAX) ++d.planRejectCount;
        if (d.planReason < 32) d.planRejectReasons |= 1u << d.planReason;
        // Preserve the latest rejection even when airportd immediately starts
        // another successful scan before the user can collect the report.
        d.lastPlanFailure = nativeScan.plan.diagnostic;
        d.lastPlanFailureRequest = d.requests;
    }
    switch (result) {
        case ScanPlanStatus::BadArgument:
            nativeScan.diagnostics.rejectStage = RejectPlan;
            return finishRequest(kIOReturnBadArgument);
        case ScanPlanStatus::Unsupported:
            nativeScan.diagnostics.rejectStage = RejectPlan;
            return finishRequest(kIOReturnUnsupported);
        case ScanPlanStatus::NoSpace:
            nativeScan.diagnostics.rejectStage = RejectPlan;
            return finishRequest(kIOReturnNoSpace);
        case ScanPlanStatus::Success: break;
    }
    // After a successful prepare the associated plan records the serving BSS
    // channel: the HAL derives the fragmented passive wire request from it and
    // the health gate measures non-AP channel evidence against it.
    if (admitAssociated)
        nativeScan.plan.markAssociatedScan(ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan));
    if (!nativeScan.begin()) {
        nativeScan.diagnostics.rejectStage = RejectBegin;
        return finishRequest(kIOReturnBusy);
    }
    publishNativeScanDiagnostics();
    const auto scheduled = nativeScanTimer->setTimeoutMS(10);
    if (scheduled != kIOReturnSuccess) {
        nativeScan.diagnostics.rejectStage = RejectTimer;
        nativeScan.workerFinished();
        nativeScan.delivery.discardForDetach();
        return finishRequest(scheduled);
    }
    if (!nativeScanCall->enter()) {
        nativeScan.diagnostics.rejectStage = RejectThreadcall;
        nativeScan.workerFinished();
        nativeScan.delivery.discardForDetach();
        return finishRequest(kIOReturnNotReady);
    }
    // Q9 baseline: the WCL scan-cache queue entry count before this scan runs,
    // so the after-read at delivery completion shows whether entries persist.
    {
        uint64_t count = 0;
        void *store = nullptr, *queue = nullptr;
        if (itlwmReadWclCacheQueueCount(fNetIf, &count, &store, &queue)) {
            nativeScan.diagnostics.wclCacheCountBefore =
                count > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(count);
            nativeScan.diagnostics.wclCacheStorePtr = reinterpret_cast<uint64_t>(store);
            nativeScan.diagnostics.wclCacheQueuePtr = reinterpret_cast<uint64_t>(queue);
        } else {
            nativeScan.diagnostics.wclCacheReadError |= 1u;
        }
    }
    return finishRequest(kIOReturnSuccess);
}

IOReturn AirportItlwm::cancelNativeScan()
{
    if (!_fWorkloop->inGate()) return kIOReturnCannotLock;
    if (!nativeScan.workerActive()) return kIOReturnSuccess;
    nativeScan.cancel();
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    if (hal) hal->cancelNativeScan();
    return kIOReturnSuccess;
}

// A WCL join/leave request has synchronous semantics.  A background scan is
// preemptible, but returning Busy while it is still in flight leaves Apple's
// network FSM with a failed transition when the user toggles Wi-Fi quickly.
// Cancel the scan through the audited HAL path and wait for the worker's real
// stop barrier before admitting the next radio operation.  Once the worker is
// stopped, run the same timer delivery path once so a canceled scan's failure
// completion is acknowledged before a new join can be admitted.  We never
// force-clear its delivery state or treat cancellation as a successful scan.
IOReturn AirportItlwm::cancelAndWaitNativeScan()
{
    if (!_fWorkloop || !_fWorkloop->inGate()) return kIOReturnCannotLock;
    if (!nativeScan.workerActive()) return kIOReturnSuccess;
    const auto canceled = cancelNativeScan();
    if (canceled != kIOReturnSuccess) return canceled;
    while (nativeScan.workerActive() && nativeAvailable())
        _fCommandGate->commandSleep(&nativeScan, THREAD_UNINT);
    if (!nativeAvailable()) return kIOReturnNotReady;
    if (nativeScan.delivery.busy() && nativeScanTimer)
        nativeScanTimerAction(this, nativeScanTimer);
    return nativeScan.delivery.busy() ? kIOReturnBusy : kIOReturnSuccess;
}

void AirportItlwm::nativeScanWorker(thread_call_param_t owner, thread_call_param_t)
{
    auto *self = static_cast<AirportItlwm *>(owner);
    self->getWorkQueue()->runAction([](OSObject *object, void *, void *, void *, void *) -> IOReturn {
        static_cast<AirportItlwm *>(object)->runNativeScan();
        return kIOReturnSuccess;
    }, self);
}

void AirportItlwm::runNativeScan()
{
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    if (nativeRadioAvailable() && power_state && !nativeScan.canceled() && hal) {
        // A background scan uses the current radio and association. Never
        // initialize the radio if that association disappeared before dispatch.
        const auto enabled = nativeScan.plan.associatedScan()
            ? (hal->nativePortReady() ? kIOReturnSuccess : kIOReturnNotReady)
            : hal->nativeEnable(bsdInterface);
        nativeScan.diagnostics.enableResult = static_cast<uint32_t>(enabled);
        // Publish before entering the synchronous HAL scan. If the transport
        // wedges while waiting for firmware, the provider still records that
        // the worker started and radio enable completed.
        publishNativeScanDiagnostics();
        if (enabled == kIOReturnSuccess && nativeRadioAvailable() && power_state && !nativeScan.canceled()) {
            ItlScan::NativeSink sink;
            sink.context = &nativeScan;
            sink.submitted = [](void *context, ItlScan::Submission result) {
                static_cast<SequoiaWCL::NativeScan *>(context)->submitted(result);
            };
            sink.notification = [](void *context, uint16_t code, const void *bytes, size_t size) {
                static_cast<SequoiaWCL::NativeScan *>(context)->notification(code, bytes, size);
            };
            sink.failed = [](void *context, ItlScan::Outcome outcome) {
                static_cast<SequoiaWCL::NativeScan *>(context)->failed(outcome);
            };
            sink.stopped = [](void *context) {
                static_cast<SequoiaWCL::NativeScan *>(context)->hardwareStopped();
            };
            const int error = hal->nativeScan(nativeScan.plan, sink);
            // Keep the legacy IWM diversity guard for its opt-in scan path.
            // IWX uses the firmware background scheduler; its actual per-channel
            // completion coverage remains mandatory in NativeScan.
            nativeScan.finishAssociatedScan(!hal->nativeAssociatedScanSupported());
            nativeScan.diagnostics.cache = hal->nativeCacheDiagnostic;
            nativeScan.diagnostics.nativeScanResult = static_cast<uint32_t>(error);
            setProperty("SequoiaNativeScanError", static_cast<uint64_t>(error), 32);
            publishNativeScanDiagnostics();
        } else if (enabled == kIOReturnSuccess && !nativeScan.plan.associatedScan()) {
            // Cancellation may have arrived while radio initialization slept.
            hal->nativeDisable(bsdInterface);
        }
        publishNativeScanDiagnostics();
    }
    nativeScan.workerFinished();
    _fCommandGate->commandWakeup(&nativeScan, false);
    if (nativeAvailable()) nativeScanTimer->setTimeoutMS(1);
}

// r223: the pending-event queue route drops every WCL scan message
// (IO80211Glue::receiveMessageInternal's WCL branch hands a stale pre-allocated
// message to WCLGlue, so the re-encoded msgIndex matches no handler). The kernel
// build installs the direct route - a WCLBulletinBoard::sendMessage call
// implemented in SequoiaPeerFactory.cpp - from startNative in
// native_lifecycle_sequoia.inc through itlwmSetWclDirectPostRoute below. That
// file is included before this one, so the install has to go through a setter;
// r223/d149 declared a same-named function-scope pointer at the install site
// instead, which left this one null and made the whole direct route dead code.
// Host tests and the iwm transport never call the setter, so deliveries fall
// back to the interface queue there.
static SequoiaWCL::WclDirectPostRoute itlwmWclDirectPostRoute = nullptr;

void itlwmSetWclDirectPostRoute(SequoiaWCL::WclDirectPostRoute route)
{
    __atomic_store_n(&itlwmWclDirectPostRoute, route, __ATOMIC_RELEASE);
}

namespace {
// The native producer has two audited WCL result routes.  The cache route is
// the current default (0xce); the FSM route (0xc9) was the only route that
// produced requester-visible network counts on r162/r163.  Keep the choice
// boot-argument controlled so one signed trial can distinguish the two
// consumers, and allow a bounded dual post for the cache-plus-requester test.
enum : uint32_t {
    kNativeScanRouteCache = 0,
    kNativeScanRouteFsm = 1,
    kNativeScanRouteDual = 2,
    // r224: also post INFRA_SCAN_START (0x7d) before the first result and
    // INFRA_SCAN_COMPLETE (0x7e) after the completion, to drive the scan FSM
    // into IN_PROGRESS.  The existing 0xc9/0xce/0xed stream is unchanged; this
    // only adds the firmware-event markers Apple's driver also emits.
    kNativeScanRouteStart = 3,
};

static uint32_t nativeScanRouteOverride();
static uint32_t nativeScanDoneRouteOverride();

static uint32_t nativeScanResultRoute()
{
    const uint32_t override = nativeScanRouteOverride();
    if (override <= kNativeScanRouteStart) return override;
    char route[8] = {};
    if (!PE_parse_boot_argn("itlwm_scan_route", route, sizeof(route)))
        return kNativeScanRouteDual;
    if (!strcmp(route, "fsm")) return kNativeScanRouteFsm;
    if (!strcmp(route, "cache")) return kNativeScanRouteCache;
    if (!strcmp(route, "start")) return kNativeScanRouteStart;
    if (!strcmp(route, "dual")) return kNativeScanRouteDual;
    return kNativeScanRouteDual;
}

// Message 10 is the old BSD/airportd transaction completion, separate from
// WCL's 0xed completion.  The pre-Skywalk driver emits it through the
// interface object, while the native WCL path uses the controller's
// IOReturn-producing postMessage for 0xed.  Keep both routes selectable for a
// single boot; the interface route is the default because airportd's live log
// says it never observes the controller-posted outer event.
enum : uint32_t {
    kNativeScanDoneRouteInterface = 0,
    kNativeScanDoneRouteController = 1,
};

static uint32_t nativeScanDoneRoute()
{
    const uint32_t override = nativeScanDoneRouteOverride();
    if (override <= kNativeScanDoneRouteController) return override;
    char route[16] = {};
    if (!PE_parse_boot_argn("itlwm_scan_done_route", route, sizeof(route)))
        return kNativeScanDoneRouteInterface;
    if (!strcmp(route, "controller")) return kNativeScanDoneRouteController;
    return kNativeScanDoneRouteInterface;
}

// These atomics are deliberately tiny and independent of the scan buffers:
// changing a debug route cannot race with delivery storage or firmware state.
static uint32_t gNativeScanRouteOverride = UINT32_MAX;
static uint32_t gNativeScanDoneRouteOverride = UINT32_MAX;

static uint32_t nativeScanRouteOverride()
{
    return __atomic_load_n(&gNativeScanRouteOverride, __ATOMIC_ACQUIRE);
}

static uint32_t nativeScanDoneRouteOverride()
{
    return __atomic_load_n(&gNativeScanDoneRouteOverride, __ATOMIC_ACQUIRE);
}

static void setNativeScanRouteOverride(uint32_t value)
{
    __atomic_store_n(&gNativeScanRouteOverride, value, __ATOMIC_RELEASE);
}

static void setNativeScanDoneRouteOverride(uint32_t value)
{
    __atomic_store_n(&gNativeScanDoneRouteOverride, value, __ATOMIC_RELEASE);
}

// Hands the scan delivery's post step to the interface's own postMessage. It is a
// member template with a deduced return so this file still compiles where the host
// tests instantiate it, which is without IOWorkLoop or the interface type in scope.
template <typename Controller>
struct ScanDeliveryPostAdapter {
    Controller *controller;
    uint32_t resultRoute;
    auto *getWorkQueue() const { return controller->getWorkQueue(); }
    template <typename Interface>
    int postMessage(Interface *interface, uint32_t kind, void *bytes, size_t size, bool dispatch)
    {
        auto &diag = controller->nativeScan.diagnostics;
        // The direct route ends at the same WCLBulletinBoard::sendMessage(board, 12,
        // msg) that WCLGlue::receiveMessageInternal reaches, but it RETURNS the
        // first non-zero handler result (routeMsg accumulates it), which the queue
        // route only writes into its own message's +0x28 result byte where this
        // driver can never read it. That return code is the only local evidence
        // distinguishing "never reached a handler" from "a handler rejected the
        // payload". A rejected payload was not committed by the board, so it
        // falls back to the queue - Apple's own route gets a second attempt
        // without duplicating an accepted cache update - while an accepted one
        // must never be re-queued.
        const auto direct = [&diag](Interface *iface, uint32_t msgId, void *payload, size_t len) {
            const auto route = __atomic_load_n(&itlwmWclDirectPostRoute, __ATOMIC_ACQUIRE);
            if (!route) return false;
            uint32_t result = UINT32_MAX;
            if (!route(iface, msgId, payload, len, &result)) return false;
            diag.wclDirectLastResult = result;
            if (result != 0) {
                if (diag.wclDirectFailures != UINT32_MAX) ++diag.wclDirectFailures;
                if (diag.wclDirectFirstFailure == UINT32_MAX) diag.wclDirectFirstFailure = result;
                return false;
            }
            ++diag.wclDirectPosts;
            diag.lastResultMsgIndex = (msgId << 16) | SequoiaWCL::kScanResultMsgType;
            return true;
        };
        // WCLGlue::receiveMessageInternal computes the bulletin-board index itself:
        // it reads CommonGlueMessage+0x00 as the msgId, +0x04 as the msgType byte
        // (0 on this path), and stores (msgId << 16) | 2 - 24G830 at 0x12fd7. The
        // interface and the pending-event queue carry the kind unchanged, so this
        // route must post the BARE id. r221 encoded here as well, which shifted
        // twice (0xce -> 0x00ce0002 -> 0x00020002) and is why r222 still logged no
        // SCAN_RESULT; lastResultMsgIndex records the index the family will build.
        const auto queued = [&diag](Interface *iface, uint32_t msgId, void *payload, size_t len,
                                    bool dispatch) {
            diag.lastResultMsgIndex = (msgId << 16) | SequoiaWCL::kScanResultMsgType;
            iface->postMessage(msgId, payload, len, dispatch);
        };
        if (kind == SequoiaWCL::kScanResultMessage) {
            // r224: drive the scan FSM into IN_PROGRESS by posting
            // INFRA_SCAN_START (0x7d) once, before the first result.  The FSM
            // state machine otherwise drops every 0xc9/0xce result and only
            // records the trailing 0xed as a no-op transition.
            // NOTE: firmware-event ids (0x7d/0x7e/0xc6) live in msgType 0/1/4 in
            // getManagerMsgBitmap (msgType=2's range is only 0x1c), so we must
            // use the controller/interface postMessage path that Apple uses and
            // that assigns the matching msgType, NOT itlwmWclDirectPostRoute
            // which hardcodes msgType=2 (it would be dropped by the gate).
            if (resultRoute == kNativeScanRouteStart && !diag.scanSeqStarted) {
                interface->postMessage(SequoiaWCL::kInfraScanStart, nullptr, 0, dispatch);
                ++diag.wclStartPosts;
                diag.lastResultMsgIndex =
                    (SequoiaWCL::kInfraScanStart << 16) | SequoiaWCL::kScanResultMsgType;
                diag.scanSeqStarted = true;
            }
            // The direct route consumes the bytes synchronously, so a dual probe
            // can safely post both entries independently.
            if (resultRoute == kNativeScanRouteFsm || resultRoute == kNativeScanRouteDual) {
                if (!direct(interface, SequoiaWCL::kBeaconMessage, bytes, size))
                    queued(interface, SequoiaWCL::kBeaconMessage, bytes, size, dispatch);
                SequoiaWCL::NativeScan::countPhysicalPost(diag.wclResultPosts);
                SequoiaWCL::NativeScan::countPhysicalPost(diag.wclFsmResultPosts);
            }
            if (resultRoute != kNativeScanRouteFsm) {
                if (!direct(interface, SequoiaWCL::kScanResultMessage, bytes, size))
                    queued(interface, SequoiaWCL::kScanResultMessage, bytes, size, dispatch);
                SequoiaWCL::NativeScan::countPhysicalPost(diag.wclResultPosts);
                SequoiaWCL::NativeScan::countPhysicalPost(diag.wclCacheResultPosts);
            }
        } else {
            if (kind == SequoiaWCL::kScanCompleteMessage) {
                if (!direct(interface, kind, bytes, size))
                    queued(interface, kind, bytes, size, dispatch);
                SequoiaWCL::NativeScan::countPhysicalPost(diag.wclCompletionPosts);
                // r224: mirror the completion as INFRA_SCAN_COMPLETE (0x7e) so the
                // scan manager transitions the FSM back out of IN_PROGRESS.  Use
                // the interface postMessage path (correct msgType), not the
                // msgType=2 direct route.
                if (resultRoute == kNativeScanRouteStart) {
                    interface->postMessage(SequoiaWCL::kInfraScanComplete, nullptr, 0, dispatch);
                    ++diag.wclCompleteFirmwarePosts;
                }
            } else {
                queued(interface, kind, bytes, size, dispatch);
            }
        }
        return 0;
    }
};
} // namespace

// Public translation-unit hooks used by the controller's runtime property
// handler. They only touch the atomic route selectors above.
uint32_t itlwmNativeScanRouteOverride() { return nativeScanRouteOverride(); }
uint32_t itlwmNativeScanDoneRouteOverride() { return nativeScanDoneRouteOverride(); }
uint32_t itlwmNativeAssocScanOverride() { return nativeAssocScanOverride(); }
void itlwmSetNativeScanRouteOverride(uint32_t value) { setNativeScanRouteOverride(value); }
void itlwmSetNativeScanDoneRouteOverride(uint32_t value) { setNativeScanDoneRouteOverride(value); }
void itlwmSetNativeAssocScanOverride(uint32_t value) { setNativeAssocScanOverride(value); }
void itlwmSetNativeWclQueriesOverride(uint32_t value) { setNativeWclQueriesOverride(value); }

// Implemented in SequoiaPeerFactory.cpp: schedule the glue's pending-event
// source on Apple's own IO80211WorkQueue after posting a message.
bool itlwmGlueScheduleEvents(void *interface);
bool itlwmGlueWakeState(void *interface, void **gate, unsigned *wake);

static void publishGlueScheduleDiagnostics(AirportItlwm *self)
{
    if (!self || !self->fNetIf) return;
    const bool scheduled = itlwmGlueScheduleEvents(self->fNetIf);
    void *gate = nullptr;
    unsigned wake = 0;
    const bool observed = itlwmGlueWakeState(self->fNetIf, &gate, &wake);
    auto &d = self->nativeScan.diagnostics;
    d.glueScheduleResult = scheduled;
    d.glueScheduleObserved = observed;
    d.glueScheduleGate = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(gate));
    d.glueWakeByteAfterSchedule = wake;
    self->publishNativeScanDiagnostics();
}

void AirportItlwm::nativeScanTimerAction(OSObject *owner, IOTimerEventSource *timer)
{
    auto *self = static_cast<AirportItlwm *>(owner);
    if (!self->nativeAvailable()) return;
    // The delivery's post step has to reach the interface's own postMessage.
    // 24G830's IO80211SkywalkInterface::postMessageInternal is
    //
    //     xorb $0x1, %r8b             ; r8b = !parsed
    //     movq 0x110(%rdi), %rax      ; this->ivars
    //     movq 0xd8(%rax), %rax       ; ivars+0xd8 -> the glue
    //     testq %rax,%rax ; sete %r9b ; orb %r8b,%r9b
    //     jne  <postMessageSync>
    //     movq %rax, %rdi
    //     jmp  IO80211Glue::routeEventToWcl(kind, buf, size)
    //
    // so parsed=true plus the glue field is what reaches the WCL. What this timer
    // used to call - the controller's postMessage - loads
    // *(controller->ivars+0x120)+0xb08 and jumps through that object's vtable slot
    // 0x120 instead. From r158 through r160 that route reported success on
    // thousands of deliveries while the family's WCL never logged a scan-result
    // handler and the scan FSM never left SCAN_MANAGER_STATE_IN_PROGRESS because
    // it never received SCAN_MANAGER_EVENT_SCAN_RESULT. The adapter below hands the
    // same arguments to the interface, and keeps the controller for the workqueue
    // gate the delivery checks.
    const uint32_t resultRoute = nativeScanResultRoute();
    self->nativeScan.diagnostics.resultRoute = resultRoute;
    ScanDeliveryPostAdapter<AirportItlwm> adapter{self, resultRoute};
    for (unsigned budget = 0; budget < 16; ++budget) {
        const auto result = SequoiaWCL::postScanDeliveryOnWorkQueue(&adapter, self->fNetIf,
            self->nativeScan.delivery, SequoiaWCL::NativeScan::failureStatus);
        self->nativeScan.recordDelivery(result);
        if (result == SequoiaWCL::ScanDelivery::Delivery::Complete && self->fNetIf) {
            // ScanDelivery has already posted the audited 0xed WCL
            // completion. Only the outer airportd completion remains. Defer
            // it because this timer runs on the workloop's own thread; the
            // controller API requires the gate but rejects onThread=true.
            // Q9 after-read: the direct post route ran the WCL cache handlers
            // synchronously, so the queue count here reflects the cache right
            // after this scan's messages were consumed.
            {
                uint64_t count = 0;
                void *store = nullptr, *queue = nullptr;
                if (itlwmReadWclCacheQueueCount(self->fNetIf, &count, &store, &queue)) {
                    self->nativeScan.diagnostics.wclCacheCountAfter =
                        count > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(count);
                } else {
                    self->nativeScan.diagnostics.wclCacheReadError |= 2u;
                }
            }
            self->nativeScanPostStatus = self->nativeScan.delivery.lastCompletionStatus();
            __atomic_or_fetch(&self->nativeScanPostMask, 2u, __ATOMIC_RELEASE);
            if (self->nativeScanPostCall)
                self->nativeScanPostCall->enter();
        }
        self->publishNativeScanDiagnostics();
        if (result != SequoiaWCL::ScanDelivery::Delivery::Result) break;
    }
    // r162 delivered the interface events without an explicit glue drain or
    // event-source call.  That ordering is retained as an opt-in compatibility
    // mode because it is the only local boot that produced requester-visible
    // network counts.  The normal path keeps the audited source scheduling.
    if (!self->nativeWclCompatR162)
        publishGlueScheduleDiagnostics(self);
    if (self->nativeScan.workerActive() || self->nativeScan.delivery.busy() ||
        __atomic_load_n(&self->nativeScanPostMask, __ATOMIC_ACQUIRE)) timer->setTimeoutMS(10);
}

void AirportItlwm::nativeScanPostWorker(thread_call_param_t owner, thread_call_param_t)
{
    auto *self = static_cast<AirportItlwm *>(owner);
    if (!self || !_fWorkloop) return;
    _fWorkloop->runAction(nativeScanPostGated, self, nullptr, nullptr, nullptr, nullptr);
}

IOReturn AirportItlwm::nativeScanPostGated(OSObject *owner, void *, void *, void *, void *)
{
    auto *self = static_cast<AirportItlwm *>(owner);
    if (!self) return kIOReturnBadArgument;
    const auto mask = __atomic_load_n(&self->nativeScanPostMask, __ATOMIC_ACQUIRE);
    if (!mask || !self->nativeAvailable() || !self->fNetIf) return kIOReturnNotReady;
    // 0xed was posted synchronously by ScanDelivery through the controller.
    // Message 10 is the separate airportd completion.  Its default route is
    // the direct interface API used by the existing legacy fakeScanDone path;
    // the controller route remains an explicit diagnostic override.
    UInt32 messagePayload = self->nativeScanPostStatus;
    if (mask & 2u) {
        auto &d = self->nativeScan.diagnostics;
        d.legacyCompletionRoute = nativeScanDoneRoute();
        if (d.legacyCompletionAttempts != UINT32_MAX) ++d.legacyCompletionAttempts;
        if (d.legacyCompletionRoute == kNativeScanDoneRouteController) {
            if (self->postMessage(self->fNetIf, APPLE80211_M_SCAN_DONE,
                                  &messagePayload, sizeof(messagePayload), true) != 0) {
                if (self->nativeScanTimer) self->nativeScanTimer->setTimeoutMS(10);
                self->publishNativeScanDiagnostics();
                return kIOReturnIOError;
            }
            if (d.legacyCompletionControllerPosts != UINT32_MAX)
                ++d.legacyCompletionControllerPosts;
        } else {
            // This is the same four-byte status payload and direct interface
            // dispatch used by the existing legacy fakeScanDone path.  The
            // interface API has no return value, so admission is cleared only
            // after the call returns; the route and count remain observable.
            self->fNetIf->postMessage(APPLE80211_M_SCAN_DONE,
                                      &messagePayload, sizeof(messagePayload), false);
            if (d.legacyCompletionInterfacePosts != UINT32_MAX)
                ++d.legacyCompletionInterfacePosts;
        }
        if (!self->nativeWclCompatR162)
            publishGlueScheduleDiagnostics(self);
        __atomic_fetch_and(&self->nativeScanPostMask, ~2u, __ATOMIC_RELEASE);
        if (self->nativeScan.diagnostics.legacyScanDone != UINT32_MAX)
            ++self->nativeScan.diagnostics.legacyScanDone;
        self->publishNativeScanDiagnostics();
    }
    return kIOReturnSuccess;
}

void AirportItlwm::recordUnsupportedRequest(uint32_t selector, bool notReady)
{
    auto &d = nativeScan.diagnostics;
    if (notReady) {
        ++d.notReadyRequests;
        return;
    }
    ++d.unsupportedRequests;
    d.lastUnsupportedSelector = static_cast<uint32_t>(selector);
    for (unsigned i = 0; i < 4; ++i) {
        if (d.unsupportedSelectors[i] == static_cast<uint32_t>(selector)) break;
        if (d.unsupportedSelectors[i] == UINT32_MAX) {
            d.unsupportedSelectors[i] = static_cast<uint32_t>(selector);
            break;
        }
    }
    // Publish immediately: the dispatcher runs on the workqueue, and a boot that
    // ends early should still leave the last selectors visible in the black box.
    publishNativeScanDiagnostics();
}

void AirportItlwm::recordConfigurationSetter(uint32_t selector)
{
    auto &d = nativeScan.diagnostics;
    ++d.configurationSetters;
    d.lastConfigurationSetter = selector;
    publishNativeScanDiagnostics();
}

void AirportItlwm::stopNativeScan()
{
    // IOService stop/start-failure runs outside the workloop thread. Close
    // admission first, wake any sleeping scan, then join without holding gate.
    if (nativeLoopRetained)
        _fWorkloop->runAction([](OSObject *owner, void *, void *, void *, void *) -> IOReturn {
            auto *self = static_cast<AirportItlwm *>(owner);
            self->cancelNativeScan();
            if (self->nativeScanTimerAdded) {
                self->nativeScanTimer->cancelTimeout();
                self->nativeScanTimer->disable();
            }
            return kIOReturnSuccess;
        }, this);
    if (nativeScanCall) {
        if (nativeScanCall->closeAndWait()) {
            _fWorkloop->runAction([](OSObject *owner, void *, void *, void *, void *) -> IOReturn {
                auto *self = static_cast<AirportItlwm *>(owner);
                self->nativeScan.workerFinished();
                self->getCommandGate()->commandWakeup(&self->nativeScan, false);
                return kIOReturnSuccess;
            }, this);
        }
        SequoiaThreadCall::destroy(nativeScanCall);
    }
    __atomic_store_n(&nativeScanPostMask, 0u, __ATOMIC_RELEASE);
    nativeScanPostStatus = 0;
    SequoiaThreadCall::destroy(nativeScanPostCall);
    if (nativeScanTimerAdded) {
        _fWorkloop->removeEventSource(nativeScanTimer);
        nativeScanTimerAdded = false;
    }
    OSSafeReleaseNULL(nativeScanTimer);
    // Physical cleanup is completed by the joined worker or the later HAL
    // detach. Storage is released only after HAL detach in stopNative.
}
