#include <Airport/SequoiaNativeScan.h>
#include <Airport/SequoiaNativeJoin.h>
#include <HAL/ItlNativeScan.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>
#include <cstring>
#include <cerrno>
#include <climits>

using IOReturn = int;
using UInt32 = uint32_t;
using UInt64 = uint64_t;
struct IOEthernetAddress { uint8_t bytes[6]; };
using thread_call_param_t = void *;
using thread_call_func_t = void (*)(void *, void *);
using AbsoluteTime = std::chrono::steady_clock::time_point;
enum { kMillisecondScale = 1000000, IWM_FLAG_SHUTDOWN = 1, IWM_FLAG_HW_ERR = 2, IWM_FLAG_RFKILL = 4 };
static std::atomic<uint64_t> testClock{1000};
static uint64_t airport_up_time() { return testClock.load(); }
static void clock_interval_to_deadline(unsigned interval, unsigned scale, AbsoluteTime *out) {
    assert(scale == kMillisecondScale);
    *out = std::chrono::steady_clock::now() + std::chrono::milliseconds(interval);
}
enum { kIOReturnSuccess, kIOReturnNotReady, kIOReturnBusy, kIOReturnBadArgument,
       kIOReturnUnsupported, kIOReturnNoSpace, kIOReturnCannotLock, kIOReturnError,
       kIOReturnIOError = kIOReturnError };
enum { IEEE80211_CHAN_MAX = 255, IEEE80211_CHAN_PASSIVE = 1, IEEE80211_CHAN_DFS = 2,
       IEEE80211_S_INIT = 0, IEEE80211_S_SCAN = 1, IEEE80211_S_AUTH = 2,
       IEEE80211_S_ASSOC = 3, IEEE80211_S_RUN = 4, THREAD_UNINT = 0, kWatchDogTimerPeriod = 1000,
       kPowerStateOff = 0, kPowerStateOn = 1, APPLE80211_VERSION = 1, IFF_RUNNING = 0x40 };
#ifndef __MAC_15_0
#define __MAC_15_0 150000
#endif
#define __IO80211_TARGET __MAC_15_0
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define isset(a, b) ((a)[(b) / 8] & (1u << ((b) % 8)))
#define IEEE80211_IS_CHAN_2GHZ(c) ((c)->ic_freq < 3000)
#define IEEE80211_IS_CHAN_5GHZ(c) ((c)->ic_freq >= 3000)
#define APPLE80211_M_SCAN_DONE 10
#define APPLE80211_M_RESET_INTERFACE 49
#define OSDynamicCast(type, p) dynamic_cast<type *>(p)
#define OSSafeReleaseNULL(p) do { if (p) { (p)->release(); (p) = nullptr; } } while (0)

// Production resolves the serving BSS channel with ieee80211_chan2ieee(ic,
// ic->ic_bss->ni_chan); the fixture's controller struct is an anonymous type
// and its faked node stores the IEEE channel number directly, so this template
// models the same call without pulling in the full net80211 header set.
template <typename Controller, typename Channel>
static unsigned ieee80211_chan2ieee(const Controller *, Channel channel) { return channel; }

static const char *testScanRoute = nullptr;
static const char *testAssocScanArg = nullptr;
static const char *testWclQueriesArg = nullptr;

// Faithful model of the kernel parsers, verified against the 24G830 KDK
// _PE_parse_boot_argn_internal disassembly: PE_parse_boot_argn stores a NUMERIC
// value as a binary integer in the buffer (width per the length argument) and
// copies only non-numeric values as a NUL-terminated string; PE_parse_boot_arg_str
// always copies the string.  r225's gate used the former with "itlwm_assoc_scan=1",
// so the device-side strcmp(value, "1") could never match.
static bool parseBootArgN(const char *name, void *value, size_t length)
{
    const char *raw = nullptr;
    if (std::strcmp(name, "itlwm_scan_route") == 0) raw = testScanRoute;
    else if (std::strcmp(name, "itlwm_assoc_scan") == 0) raw = testAssocScanArg;
    if (!raw || !value || !length) return false;
    char *end = nullptr;
    const unsigned long long numeric = std::strtoull(raw, &end, 0);
    if (end != raw && *end == '\0') {
        switch (length) {
        case 1: *static_cast<uint8_t *>(value) = static_cast<uint8_t>(numeric); break;
        case 2: *static_cast<uint16_t *>(value) = static_cast<uint16_t>(numeric); break;
        case 4: *static_cast<uint32_t *>(value) = static_cast<uint32_t>(numeric); break;
        default: *static_cast<uint64_t *>(value) = numeric; break;
        }
        return true;
    }
    std::strncpy(static_cast<char *>(value), raw, length - 1);
    static_cast<char *>(value)[length - 1] = '\0';
    return true;
}

static bool PE_parse_boot_argn(const char *name, void *value, size_t length)
{
    return parseBootArgN(name, value, length);
}

static bool PE_parse_boot_arg_str(const char *name, char *value, size_t length)
{
    const char *raw = nullptr;
    if (std::strcmp(name, "itlwm_assoc_scan") == 0) raw = testAssocScanArg;
    else if (std::strcmp(name, "itlwm_wcl_queries") == 0) raw = testWclQueriesArg;
    if (!raw || !value || !length) return false;
    std::strncpy(value, raw, length - 1);
    value[length - 1] = '\0';
    return true;
}

struct OSObject {
    virtual ~OSObject() = default;
    virtual void retain() {}
    virtual void release() {}
};
class AirportItlwm;
struct IONetworkInterface : OSObject {
    // The kernel-side scan delivery hands each message to the interface's own
    // postMessage (see ScanDeliveryPostAdapter in native_scan_sequoia.inc). This
    // stub forwards it to the single controller under test so the existing
    // postMessage assertions keep observing every delivery.
    bool bsdAttached = true;
    void *getBSDInterface() { return bsdAttached ? this : nullptr; }
    static AirportItlwm *owner;
    void postMessage(uint32_t kind, void *data, size_t size, bool dispatch);
};
struct apple80211_power_data { unsigned version = 1, num_radios = 1, power_state[4] = {}; };
static unsigned allocationFailure = 0, allocationStep = 0, allocations = 0;
static bool shouldFail() { return ++allocationStep == allocationFailure; }
static void *IOMalloc(size_t size) { if (shouldFail()) return nullptr; ++allocations; return std::malloc(size); }
static void IOFree(void *p, size_t) { assert(allocations); --allocations; std::free(p); }
static void randomBytes(void *p, size_t size) { memset(p, 2, size); }
#define arc4random_buf randomBytes
#define XYLog(...) do {} while (0)
static void IOLockLock(std::mutex *m) { m->lock(); }
static void IOLockUnlock(std::mutex *m) { m->unlock(); }
struct IOLock { std::mutex mutex; std::condition_variable changed; };
static IOLock *IOLockAlloc() { return shouldFail() ? nullptr : new IOLock; }
static void IOLockFree(IOLock *lock) { delete lock; }
static void IOLockLock(IOLock *lock) { lock->mutex.lock(); }
static void IOLockUnlock(IOLock *lock) { lock->mutex.unlock(); }
static void IOLockSleep(IOLock *lock, void *, int) {
    std::unique_lock<std::mutex> guard(lock->mutex, std::adopt_lock);
    const auto result = lock->changed.wait_for(guard, std::chrono::seconds(5));
    guard.release(); assert(result != std::cv_status::timeout);
}
static void IOLockWakeup(IOLock *lock, void *, bool) { lock->changed.notify_all(); }

class Loop {
public:
    using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);
    std::recursive_mutex gate;
    std::condition_variable_any changed;
    static thread_local Loop *current;
    bool on = false;
    bool inGate() const { return current == this; }
    bool onThread() const { assert(inGate()); return on; }
    IOReturn runAction(Action action, OSObject *owner, void *a = nullptr, void *b = nullptr,
                       void *c = nullptr, void *d = nullptr) {
        assert(!inGate());
        std::lock_guard<std::recursive_mutex> lock(gate);
        Loop *previous = current; current = this;
        const auto result = action(owner, a, b, c, d);
        current = previous;
        return result;
    }
    template <typename F> auto run(F body) -> decltype(body()) {
        assert(!inGate());
        std::lock_guard<std::recursive_mutex> lock(gate);
        Loop *previous = current; current = this;
        auto result = body();
        current = previous;
        return result;
    }
    void commandWakeup(void *, bool) { assert(inGate()); changed.notify_all(); }
    void commandSleep(void *, int) {
        assert(inGate());
        std::unique_lock<std::recursive_mutex> lock(gate, std::adopt_lock);
        const auto status = changed.wait_for(lock, std::chrono::seconds(5));
        lock.release();
        assert(status != std::cv_status::timeout);
    }
    void commandSleep(void *, AbsoluteTime deadline, int) {
        assert(inGate());
        std::unique_lock<std::recursive_mutex> lock(gate, std::adopt_lock);
        changed.wait_until(lock, deadline);
        lock.release();
        if (onTimedSleep) onTimedSleep();
    }
    std::function<void()> onTimedSleep;
    int addEventSource(OSObject *) { return shouldFail() ? kIOReturnError : kIOReturnSuccess; }
    void removeEventSource(OSObject *) {}
};
thread_local Loop *Loop::current = nullptr;
// Production keeps the Sequoia workloop as a translation-unit global; the
// fixture also exposes a per-object member for the ordinary controller paths.
// The post-completion threadcall uses this global spelling, so point it at the
// sole fixture instance while that instance is alive.
static Loop *_fWorkloop = nullptr;

// Host model of ONCE pending/running/requeued threadcalls. Explicit dispatch lets
// tests cancel a pending invocation without depending on wall-clock timing.
struct Call {
    void (*action)(void *, void *); void *owner;
    std::mutex mutex; std::condition_variable changed;
    bool pending = false, running = false, allowed = false, closing = false;
    unsigned cancelWaitCalls = 0;
    std::thread thread;
    Call(void (*a)(void *, void *), void *o) : action(a), owner(o), thread([this] {
        std::unique_lock<std::mutex> lock(mutex);
        for (;;) {
            changed.wait(lock, [&] { return closing || (pending && allowed); });
            if (closing) return;
            pending = false; running = true;
            lock.unlock(); action(owner, nullptr); lock.lock();
            running = false; changed.notify_all();
        }
    }) {}
};
using thread_call_t = Call *;
enum { THREAD_CALL_PRIORITY_HIGH = 0, THREAD_CALL_OPTIONS_ONCE = 1 };
static thread_call_t thread_call_allocate_with_options(thread_call_func_t a, void *o, int priority, int options) {
    assert(priority == THREAD_CALL_PRIORITY_HIGH && options == THREAD_CALL_OPTIONS_ONCE);
    return shouldFail() ? nullptr : new Call(a, o);
}
static bool thread_call_enter(Call *c) {
    std::lock_guard<std::mutex> lock(c->mutex);
    const bool previous = c->pending; c->pending = true; c->changed.notify_all(); return previous;
}
static bool thread_call_cancel(Call *c) {
    std::unique_lock<std::mutex> lock(c->mutex);
    const bool canceled = c->pending; c->pending = false;
    ++c->cancelWaitCalls; c->changed.notify_all();
    // Public cancel never waits, regardless of pending or running work.
    return canceled;
}
static bool thread_call_free(Call *c) {
    { std::lock_guard<std::mutex> lock(c->mutex); assert(!c->pending); c->closing = true; c->changed.notify_all(); }
    // Join only to reclaim the fixture's std::thread. Kernel thread_call_free
    // defers reclamation, so production must not access its wrapper on return.
    c->thread.join(); delete c;
    return true;
}
#include <Airport/SequoiaThreadCall.h>
static void dispatch(Call *c) {
    std::lock_guard<std::mutex> lock(c->mutex); c->allowed = true; c->changed.notify_all();
}
static void joined(Call *c) {
    std::unique_lock<std::mutex> lock(c->mutex);
    assert(c->changed.wait_for(lock, std::chrono::seconds(5), [&] { return !c->pending && !c->running; }));
}
static void dispatch(SequoiaThreadCall *state) { dispatch(state->call); }
static void joined(SequoiaThreadCall *state) { joined(state->call); }

struct IOTimerEventSource : OSObject {
    OSObject *owner; void (*action)(OSObject *, IOTimerEventSource *);
    bool armed = false, enabled = true, failSchedule = false;
    static IOTimerEventSource *timerEventSource(OSObject *o, void (*a)(OSObject *, IOTimerEventSource *)) {
        if (shouldFail()) return nullptr;
        auto *timer = new IOTimerEventSource; timer->owner = o; timer->action = a; return timer;
    }
    IOReturn setTimeoutMS(unsigned) { armed = !failSchedule; return failSchedule ? kIOReturnError : kIOReturnSuccess; }
    void cancelTimeout() { armed = false; }
    void disable() { enabled = false; }
    void enable() { enabled = true; }
    void release() { delete this; }
};

struct ItlIwm : OSObject {
    Loop *loop;
    // Production reads ic_bss->ni_chan for the associated-scan plan, so the
    // fixture models the one field the native path touches.
    struct FakeNode { uint8_t ni_chan; };
    struct {
        struct { unsigned ic_freq = 0, ic_flags = 0; } ic_channels[256];
        uint8_t ic_chan_avail[32] = {}, ic_myaddr[6] = {0x88,1,2,3,4,5};
        struct { uint8_t ac_enaddr[6] = {0x88,1,2,3,4,5}; } ic_ac;
        struct { unsigned if_flags = 0; } ic_if;
        int ic_state = IEEE80211_S_INIT;
        FakeNode *ic_bss = nullptr;
    } ic;
    std::function<void()> onEnable, onScan, onDisable;
    unsigned enables = 0, scans = 0, disables = 0;
    int enableError = 0, disableError = 0;
    ItlScan::NativeSink sink;
    bool canceled = false;
    struct { int sc_generation = 1; unsigned sc_flags = 0; } com;
    int nativeStateError = 0, joinError = 0;
    int watchdogError = 0;
    unsigned watchdogPolls = 0;
    int iwm_native_watchdog(uint64_t) {
        ++watchdogPolls;
        if (com.sc_flags & (IWM_FLAG_SHUTDOWN | IWM_FLAG_HW_ERR | IWM_FLAG_RFKILL)) return ENETDOWN;
        return watchdogError;
    }
    ItlJoin::Progress nativeJoinProgress;
    SequoiaWCL::JoinCandidateDiagnostic nativeCandidateDiagnostic;
    ItlScan::CacheDiagnostic nativeCacheDiagnostic;
    bool portReady = false;
    unsigned joins = 0;
    std::function<void()> onJoin;
    int leaveError = 0;
    unsigned leaves = 0;
    std::function<void()> onLeave;
    int iwm_native_leave(bool, uint16_t reason, unsigned waitMs) {
        assert(loop->inGate() && !loop->onThread() && reason && waitMs <= 1000);
        ++leaves; if (onLeave) onLeave(); return leaveError;
    }
    int iwm_native_join_start(const SequoiaWCL::JoinRequestSnapshot &request, size_t index) {
        assert(loop->inGate() && !loop->onThread() && index == 0 && request.get());
        ++joins;
        assert(nativeJoinProgress.begin(request.get()->candidates[0].bssid, com.sc_generation));
        if (onJoin) onJoin();
        return joinError;
    }
    auto get80211Controller() -> decltype(&ic) { return &ic; }
    IOReturn enable(IONetworkInterface *) { assert(false && "native controller used legacy HAL enable"); return kIOReturnError; }
    IOReturn disable(IONetworkInterface *) { assert(false && "native controller used legacy HAL disable"); return kIOReturnError; }
    IOReturn nativeEnable(IONetworkInterface *) { assert(loop->inGate()); ++enables; if (onEnable) onEnable(); return enableError; }
    IOReturn nativeDisable(IONetworkInterface *) {
        assert(loop->inGate()); ++disables;
        if (onDisable) onDisable();
        if (!disableError) { nativeJoinProgress.clear(); portReady = false; ++com.sc_generation; nativeStateError = 0; }
        return disableError;
    }
    int iwm_native_scan(const SequoiaWCL::ScanPlan &, const ItlScan::NativeSink &s) {
        assert(loop->inGate()); ++scans; sink = s; canceled = false;
        sink.submitted(sink.context, ItlScan::Submission::Accepted);
        if (onScan) onScan();
        if (canceled) sink.failed(sink.context, ItlScan::Outcome::Aborted);
        else {
            uint8_t iteration[28] = {}; iteration[0] = 2; iteration[1] = 1;
            iteration[12] = 1; iteration[13] = 1; iteration[20] = 36;
            uint8_t terminal[12] = {}; terminal[2] = 1;
            sink.notification(sink.context, 0xe7, iteration, sizeof(iteration));
            sink.notification(sink.context, 0x6d, terminal, sizeof(terminal));
        }
        sink.stopped(sink.context); sink = {};
        return canceled ? kIOReturnError : 0;
    }
    void iwm_native_scan_cancel() { assert(loop->inGate()); canceled = true; loop->commandWakeup(this, false); }

    // Keep this fixture aligned with the production Airport layer's
    // generation-independent ItlNativeHal boundary.  The transport remains
    // mocked here; these forwards let the controller integration test cover
    // the same admission and cancellation calls used by IWM and IWX.
    bool associatedScanSupported = false;
    bool nativeAssociatedScanSupported() const { return associatedScanSupported; }
    ItlIwm *getNativeHal() { return this; }
    auto nativeController() { return &ic; }
    int nativeScan(const SequoiaWCL::ScanPlan &plan, const ItlScan::NativeSink &s) {
        return iwm_native_scan(plan, s);
    }
    void cancelNativeScan() { iwm_native_scan_cancel(); }
    int nativeJoinStart(const SequoiaWCL::JoinRequestSnapshot &request, size_t index) {
        return iwm_native_join_start(request, index);
    }
    int nativeLeave(bool deauthenticate, uint16_t reason, unsigned waitMs) {
        return iwm_native_leave(deauthenticate, reason, waitMs);
    }
    int nativeWatchdog(uint64_t nowMs) { return iwm_native_watchdog(nowMs); }
    void nativeJoinEvent(const ItlJoin::Event &) {}
    bool nativePortReady() const { return portReady; }
    void nativeClearKeys() {}
    bool detached = false, transportReady = true;
    bool nativeDetachedState() const { return detached; }
    bool nativeCommandTransportReady() const { return transportReady; }
    int nativeStateErrorCode() const { return nativeStateError; }
    int nativeGeneration() const { return com.sc_generation; }
    const ItlJoin::Progress &nativeJoinProgressState() const { return nativeJoinProgress; }
};

class AirportItlwm : public OSObject {
public:
    Loop loop, *workloopMember = &loop, *_fCommandGate = &loop;
    IONetworkInterface interface, *bsdInterface = &interface, *fNetIf = &interface;
    bool nativeSkywalkBSDOwner = false;
    ItlIwm hal; ItlIwm *fHalService = &hal;
    IOTimerEventSource watchdog, *watchdogTimer = &watchdog;
    SequoiaWCL::NativeScan nativeScan;
    SequoiaWCL::NativeJoin nativeJoin;
    SequoiaThreadCall *nativeJoinCall = nullptr;
    IOTimerEventSource *nativeJoinTimer = nullptr;
    bool nativeJoinTimerAdded = false;
    unsigned linkUps = 0, linkDowns = 0;
    int linkError = 0;
    std::vector<uint32_t> joinMessages;
    std::vector<SequoiaWCL::LinkStatusEvent> linkEvents;
    SequoiaWCL::ConnectionCompleteEvent lastJoinCompletion = {};
    SequoiaWCL::ScanDelivery::Slot *nativeScanStorage = nullptr;
    SequoiaThreadCall *nativeScanCall = nullptr;
    SequoiaThreadCall *nativeScanPostCall = nullptr;
    uint32_t nativeScanPostMask = 0;
    uint32_t nativeScanPostStatus = 0;
    bool nativeWclCompatR162 = false;
    SequoiaThreadCall *powerOffThreadCall = nullptr, *powerOnThreadCall = nullptr;
    IOTimerEventSource *nativeScanTimer = nullptr;
    bool nativeScanTimerAdded = false, nativeLoopRetained = true, ready = true, pmOn = true;
    bool nativeRadioTransition = false;
    bool nativeFirmwareAnnounced = false;
    unsigned firmwareAnnouncements = 0;
    uint32_t nativeMacRequests = 0, nativeMacChanges = 0;
    std::mutex pmMutex, *nativePMLock = &pmMutex;
    unsigned pmPowerState = kPowerStateOn;
    struct Policy { unsigned acks = 0; void acknowledgeSetPowerState() { ++acks; } } policy, *pmPolicyMaker = &policy;
    unsigned power_state = 1, posts = 0, postFailures = 0;
    unsigned completionFailures = 0;
    // Counts scan completions that arrived as the BARE message id. WCLGlue's
    // receiveMessageInternal builds the bulletin index itself as (kind << 16) | 2,
    // so a producer that pre-encodes double-shifts (r221/r222 posted 0xce0002 and
    // the board saw 0x00020002, which matches no handler). A test that only watched
    // post counts could not tell the two apart; this one can.
    unsigned bareScanCompletions = 0;
    unsigned legacyDone = 0;
    uint32_t completion = UINT32_MAX;
    std::atomic<unsigned> references{1};
    std::function<void()> beforeRelease;
    AirportItlwm() {
        ::_fWorkloop = &loop;
        hal.loop = &loop;
        for (auto c : {1u,36u}) { hal.ic.ic_channels[c].ic_freq = c == 1 ? 2412 : 5180; hal.ic.ic_chan_avail[c / 8] |= 1u << (c % 8); }
    }
    bool nativeAvailable() { assert(loop.inGate()); return ready; }
    bool nativeRadioAvailable() { return loop.inGate() && ready && pmOn && pmPowerState == kPowerStateOn && !nativeRadioTransition; }
    Loop *getWorkQueue() { IONetworkInterface::owner = this; return &loop; }
    Loop *getCommandGate() { return &loop; }
    void retain() { ++references; }
    void release() {
        auto callback = beforeRelease;
        beforeRelease = nullptr;
        if (callback) callback();
        assert(references.fetch_sub(1) > 1);
    }
    uint32_t wakeError = UINT32_MAX, wakeRetries = 0;
    void setProperty(const char *name, uint64_t value, unsigned) {
        if (!strcmp(name, "SequoiaNativePowerOnError")) wakeError = static_cast<uint32_t>(value);
        if (!strcmp(name, "SequoiaNativePowerOnCleanupRetries")) wakeRetries = static_cast<uint32_t>(value);
    }
    void setProperty(const char *, bool) {}
    AirportItlwm *getProvider() { return this; }
    IOReturn setHardwareAddress(const void *, UInt32);
    void drainNativeRadioTransition();
    int postMessage(IONetworkInterface *, uint32_t kind, void *p, size_t size, bool sendToWcl) {
        assert(loop.inGate());
        if (postFailures) { --postFailures; return kIOReturnError; }
        if (kind == SequoiaWCL::kConnectionCompleteMessage && completionFailures) {
            --completionFailures; return kIOReturnError;
        }
        if (kind == APPLE80211_M_RESET_INTERFACE) {
            uint32_t complete = 0;
            assert(p && size == 4 && sendToWcl && power_state == 1 && hal.enables > 0);
            memcpy(&complete, p, 4);
            assert(complete == 1);
            ++firmwareAnnouncements;
            return 0;
        }
        if (kind == APPLE80211_M_SCAN_DONE) {
            assert(size == sizeof(uint32_t) && p);
            ++legacyDone;
            return 0;
        }
        ++posts;
        if (kind == SequoiaWCL::kAssocEventMessage) {
            assert(sendToWcl);
            assert(size == sizeof(SequoiaWCL::AssocEvent)); joinMessages.push_back(kind);
        }
        if (kind == SequoiaWCL::kConnectionCompleteMessage) {
            assert(sendToWcl);
            assert(size == sizeof(lastJoinCompletion)); memcpy(&lastJoinCompletion, p, size); joinMessages.push_back(kind);
        }
        if (kind == SequoiaWCL::kLinkStatusMessage) {
            assert(sendToWcl && p && size == 12);
            SequoiaWCL::LinkStatusEvent link;
            memcpy(&link, p, size);
            assert(link.up <= 1 && link.debounce == 0 && link.reason == 0xff);
            assert(!memcmp(link.bssid, nativeJoin.completion.candidates[0].bssid, 6));
            if (link.up) assert(nativePortAvailable() && nativeJoin.associationPosted && !nativeJoin.completionPosted);
            else assert(nativeJoin.drained && !nativeJoin.worker && nativeJoin.linkUpPosted);
            linkEvents.push_back(link); joinMessages.push_back(kind);
        }
        if (kind == SequoiaWCL::kJoinAbortCompleteMessage) {
            assert(sendToWcl);
            assert(size == 0 && !p && nativeJoin.drained && !nativeJoin.worker); joinMessages.push_back(kind);
        }
        if (kind == SequoiaWCL::kScanCompleteMessage) { assert(size == 4); memcpy(&completion, p, 4); }
        return 0;
    }
    bool initNativeScan();
    bool initNativeJoin();
    void stopNativeJoin();
    IOReturn requestNativeJoin(void *);
    IOReturn cancelNativeJoin(bool);
    IOReturn requestNativeLink(void *);
    IOReturn finishNativeLinkConfiguration();
    IOReturn requestNativeLeave(void *);
    void scheduleNativeJoin();
    void runNativeJoin();
    void serviceNativeJoin();
    static void nativeJoinWorker(void *, void *);
    static void nativeJoinTimerAction(OSObject *, IOTimerEventSource *);
    bool nativePortAvailable() { return hal.portReady && nativeRadioAvailable() && !hal.nativeStateError && !hal.com.sc_flags; }
    IOReturn publishNativeLink(bool up, unsigned) {
        assert(loop.inGate());
        if (up) { assert(nativePortAvailable()); ++linkUps; } else ++linkDowns;
        return linkError;
    }
    IOReturn requestNativeScan(void *);
    IOReturn cancelNativeScan();
    IOReturn cancelAndWaitNativeScan();
    void runNativeScan();
    void publishNativeScanDiagnostics() {}
    void publishNativeJoinDiagnostics() {}
    void captureNativeJoinDiagnostics(bool reset = false) {
        if (reset) nativeJoin.diagnostics.handshake = {};
        else nativeJoin.diagnostics.handshake.eapol.rxM1 = 17;
    }
    // Defined out of line in native_scan_sequoia.inc, which this test compiles.
    void recordUnsupportedRequest(uint32_t, bool);
    void recordConfigurationSetter(uint32_t);
    bool nativeWclQueriesEnabled();
    void recordWclQuery(uint32_t);
    void stopNativeScan();
    static void nativeScanWorker(void *, void *);
    static void nativeScanPostWorker(void *, void *);
    static IOReturn nativeScanPostGated(OSObject *, void *, void *, void *, void *);
    static void nativeScanTimerAction(OSObject *, IOTimerEventSource *);
    IOReturn enableAdapter(IONetworkInterface *);
    IOReturn disableAdapter(IONetworkInterface *);
    IOReturn setPOWER(OSObject *, apple80211_power_data *);
    IOReturn getPOWER(OSObject *, apple80211_power_data *);
    void setPowerStateOff();
    void setPowerStateOn();
    void unregistPM();
    void stop() {
        loop.run([&] { ready = false; return 0; });
        stopNativeScan();
        stopNativeJoin();
        assert(references == 1 && !hal.sink.valid());
        if (nativeScanStorage) {
            assert(!nativeScan.workerActive());
            assert(nativeScan.delivery.releaseStorage());
            IOFree(nativeScanStorage, sizeof(*nativeScanStorage) * SequoiaWCL::ScanDelivery::MaxSlots);
            nativeScanStorage = nullptr;
        }
    }
    void deliver() {
        loop.run([&] { nativeScanTimerAction(this, nativeScanTimer); return 0; });
        // The production timer cannot invoke the controller's postMessage on
        // its own workloop thread, so the fixture explicitly dispatches the
        // deferred outer completion threadcall after each timer tick.
        if (nativeScanPostCall) {
            dispatch(nativeScanPostCall);
            joined(nativeScanPostCall);
        }
    }
};
#include "../AirportItlwm/native_scan_sequoia.inc"
#include "../AirportItlwm/native_join_sequoia.inc"
#include "sequoia_scan_controller_methods.inc"
// Exercise the actual Apple callback as well as the controller it forwards to.
struct ether_addr { uint8_t octet[6]; };
struct AirportItlwmSkywalkInterface {
    AirportItlwm *instance;
    IOReturn setMacAddress(ether_addr &);
};
#include "sequoia_mac_callback.inc"


// Q9 WCL cache queue readback stub. The kernel implementation walks the live
// 24G830 object chain; the fixture supplies the same counters and pointers so
// the admission baseline and the post-completion read are both observable.
static uint64_t fakeWclCacheCount = 0;
static void *fakeWclCacheStore = nullptr, *fakeWclCacheQueue = nullptr;
static bool fakeWclCacheCountResolves = true;
bool itlwmReadWclCacheQueueCount(void *interface, uint64_t *count, void **cacheStore, void **queue)
{
    assert(interface);
    if (!fakeWclCacheCountResolves) return false;
    if (count) *count = fakeWclCacheCount;
    if (cacheStore) *cacheStore = fakeWclCacheStore;
    if (queue) *queue = fakeWclCacheQueue;
    return true;
}

static SequoiaWCL::ScanRequest request();

static void routeTests()
{
    testScanRoute = nullptr;
    // Check the boot-argument parser contract without allocating a native
    // session or touching hardware. The adapter's route fan-out is bounded by
    // this same parsed value and is compiled in the production translation unit.
    // The default route and the fallback for an unrecognised value are both dual,
    // because dual emits both the FSM result and the cache-update message.
    assert(nativeScanResultRoute() == 2);
    testScanRoute = "fsm";
    assert(nativeScanResultRoute() == 1);
    testScanRoute = "dual";
    assert(nativeScanResultRoute() == 2);
    testScanRoute = "invalid";
    assert(nativeScanResultRoute() == 2);
    testScanRoute = nullptr;
    // r225 associated-scan gate: off unless the override or the boot-arg
    // enables it. The fixture's PE handlers answer only when a test arg is
    // set, so the boot-arg fallback must come back disabled by default.
    itlwmSetNativeAssocScanOverride(UINT32_MAX);
    assert(!nativeAssocScanEnabled());
    itlwmSetNativeAssocScanOverride(0);
    assert(!nativeAssocScanEnabled());
    itlwmSetNativeAssocScanOverride(1);
    assert(nativeAssocScanEnabled());
    itlwmSetNativeAssocScanOverride(UINT32_MAX);
    assert(!nativeAssocScanEnabled());
    // r226 regression anchor: PE_parse_boot_argn("itlwm_assoc_scan=1") stores
    // the binary integer 1, which is exactly why r225's strcmp-based gate read
    // "on" as disabled and 67 associated scans were refused with reason 5.
    {
        char numeric[8] = {};
        testAssocScanArg = "1";
        assert(PE_parse_boot_argn("itlwm_assoc_scan", numeric, sizeof(numeric)));
        assert(numeric[0] == 1 && numeric[1] == 0);
        assert(std::strcmp(numeric, "1") != 0);
    }
    // The string parser copies the value textually; both accepted spellings
    // now enable the gate and the numeric spellings that are not "1" do not.
    testAssocScanArg = "1";
    assert(nativeAssocScanEnabled());
    testAssocScanArg = "on";
    assert(nativeAssocScanEnabled());
    testAssocScanArg = "0";
    assert(!nativeAssocScanEnabled());
    testAssocScanArg = "dual";
    assert(!nativeAssocScanEnabled());
    testAssocScanArg = nullptr;
    assert(!nativeAssocScanEnabled());
    // r227 WCL capability-query gate: override paths match the assoc gate, the
    // boot-arg default is ON, and only the two textual "off" spellings disable
    // it (string parser, so "0"/"1"/"on"/"junk" all keep it on unlike r225).
    itlwmSetNativeWclQueriesOverride(UINT32_MAX);
    assert(nativeWclQueriesGateEnabled());
    itlwmSetNativeWclQueriesOverride(0);
    assert(!nativeWclQueriesGateEnabled());
    itlwmSetNativeWclQueriesOverride(1);
    assert(nativeWclQueriesGateEnabled());
    itlwmSetNativeWclQueriesOverride(UINT32_MAX);
    testWclQueriesArg = nullptr;
    assert(nativeWclQueriesGateEnabled());
    testWclQueriesArg = "off";
    assert(!nativeWclQueriesGateEnabled());
    testWclQueriesArg = "0";
    assert(!nativeWclQueriesGateEnabled());
    testWclQueriesArg = "on";
    assert(nativeWclQueriesGateEnabled());
    testWclQueriesArg = "1";
    assert(nativeWclQueriesGateEnabled());
    testWclQueriesArg = "junk";
    assert(nativeWclQueriesGateEnabled());
    testWclQueriesArg = nullptr;
    assert(nativeWclQueriesGateEnabled());
}

static void assocScanTests()
{
    ItlIwm::FakeNode node{1};
    // Gate off: an associated request is refused with the plan's Associated
    // reason, exactly as r224 behaved, and no worker is scheduled.
    {
        AirportItlwm d;
        assert(d.initNativeScan());
        auto r = request();
        d.hal.ic.ic_state = IEEE80211_S_RUN;
        d.hal.ic.ic_bss = &node;
        d.hal.portReady = true;
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnUnsupported);
        assert(d.nativeScan.diagnostics.planReason ==
               static_cast<uint32_t>(SequoiaWCL::ScanPlanReason::Associated));
        assert(d.nativeScan.diagnostics.assocScanEnabled == 0);
        assert(!d.nativeScan.workerActive() && !d.hal.scans);
        d.stop();
    }
    // IWX capability admits connected scans by default. A quiet/directed
    // request with valid channel completion is not a diversity failure.
    for (unsigned fault = 0; fault < 3; ++fault) {
        AirportItlwm d;
        assert(d.initNativeScan());
        auto r = request();
        d.hal.associatedScanSupported = true;
        d.hal.ic.ic_state = IEEE80211_S_RUN;
        d.hal.ic.ic_bss = &node;
        d.hal.portReady = fault != 1;
        if (fault == 2) itlwmSetNativeAssocScanOverride(0);
        const auto result = d.loop.run([&] { return d.requestNativeScan(&r); });
        if (fault == 2) assert(result == kIOReturnUnsupported && !d.hal.scans);
        else {
            assert(result == kIOReturnSuccess);
            dispatch(d.nativeScanCall); joined(d.nativeScanCall); d.deliver();
            assert(d.hal.enables == 0 && d.hal.disables == 0);
            assert(d.hal.scans == (fault == 0));
            if (!fault) assert(d.completion == 0 && !d.nativeScan.diagnostics.assocWithheld);
        }
        d.stop();
        itlwmSetNativeAssocScanOverride(UINT32_MAX);
    }
    itlwmSetNativeAssocScanOverride(1);
    // Gate on, healthy result: beacons on both inventory channels, so the set
    // is delivered and the completion posts success.
    for (unsigned listCase = 0; listCase < 3; ++listCase) {
        AirportItlwm d;
        assert(d.initNativeScan());
        auto r = request();
        // Apple's empty list is one zeroed wildcard; a directed list adds
        // that same terminal wildcard. Both must deliver unrelated beacons.
        if (listCase) r.ssidCount = listCase;
        if (listCase == 2) {
            r.ssids[0].version = 1;
            r.ssids[0].length = 1;
            r.ssids[0].bytes[0] = 'x';
        }
        d.hal.ic.ic_state = IEEE80211_S_RUN;
        d.hal.ic.ic_bss = &node;
        d.hal.portReady = true;
        d.hal.onScan = [&] {
            uint8_t phy[72] = {}; phy[22] = 1; phy[28] = 55;
            uint8_t mpdu[46] = {}; mpdu[0] = 38; mpdu[4] = 0x80; mpdu[20] = 2; mpdu[42] = 3;
            for (unsigned n = 0; n < 6; ++n) {
                d.hal.sink.notification(d.hal.sink.context, 0xc0, phy, sizeof(phy));
                d.hal.sink.notification(d.hal.sink.context, 0xc1, mpdu, sizeof(mpdu));
            }
            phy[22] = 36;
            d.hal.sink.notification(d.hal.sink.context, 0xc0, phy, sizeof(phy));
            for (unsigned n = 0; n < 6; ++n)
                d.hal.sink.notification(d.hal.sink.context, 0xc1, mpdu, sizeof(mpdu));
        };
        fakeWclCacheCount = 3;
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
        const auto &diag = d.nativeScan.diagnostics;
        assert(diag.assocScanEnabled == 1 && diag.wclCacheCountBefore == 3 &&
               !diag.wclCacheReadError);
        dispatch(d.nativeScanCall); joined(d.nativeScanCall);
        assert(diag.assocScans == 1 && diag.assocApChannel == 1 &&
               diag.assocBeaconsQueued == 12 && diag.assocLastOutcome == 0 &&
               !diag.assocWithheld && diag.assocBeaconChannels == 2);
        fakeWclCacheCount = 5;
        d.deliver();
        // Dual route posts each of the 12 beacons twice (0xc9 + 0xce) and the
        // completion once.
        assert(d.posts == 25 && d.completion == 0);
        assert(diag.wclCacheCountAfter == 5 && !diag.wclCacheReadError);
        d.stop();
    }
    // Gate on, unhealthy result: the mock scan queues no beacons at all, so
    // the health gate withholds the result and the completion goes out as the
    // mapped failure, discarding the WCL generation instead of committing an
    // AP-only (here: empty) set over the cached list.
    {
        AirportItlwm d;
        assert(d.initNativeScan());
        auto r = request();
        d.hal.ic.ic_state = IEEE80211_S_RUN;
        d.hal.ic.ic_bss = &node;
        d.hal.portReady = true;
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
        dispatch(d.nativeScanCall); joined(d.nativeScanCall);
        const auto &diag = d.nativeScan.diagnostics;
        assert(diag.assocLastOutcome == 1 && diag.assocWithheld == 1 &&
               diag.assocWithheldReason == 1);
        d.deliver();
        assert(d.posts == 1 && d.completion == 0xe3ff8100);
        d.stop();
    }
    // Broken Q9 chain: both reads record the error bit and zero counts.
    {
        AirportItlwm d;
        assert(d.initNativeScan());
        auto r = request();
        d.hal.ic.ic_state = IEEE80211_S_RUN;
        d.hal.ic.ic_bss = &node;
        d.hal.portReady = true;
        fakeWclCacheCountResolves = false;
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
        dispatch(d.nativeScanCall); joined(d.nativeScanCall); d.deliver();
        const auto &diag = d.nativeScan.diagnostics;
        assert(diag.wclCacheReadError == 3 && !diag.wclCacheCountBefore &&
               !diag.wclCacheCountAfter);
        fakeWclCacheCountResolves = true;
        d.stop();
    }
    itlwmSetNativeAssocScanOverride(UINT32_MAX);
}

static SequoiaWCL::ScanRequest request()
{
    SequoiaWCL::ScanRequest r = {}; r.version = 1; r.scanType = 2; r.privateMAC = 1; r.passiveDwell = 110; return r;
}

static void tests()
{
    // A rejected request must not schedule a worker. A subsequent accepted
    // request must not erase the channel evidence before the user reads it.
    {
        AirportItlwm d;
        assert(d.initNativeScan());
        auto r = request();
        r.channelCount = 1;
        r.channels[0] = {1, 196, SequoiaWCL::Width20MHz | SequoiaWCL::Band5GHz};
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnUnsupported);
        const auto &diag = d.nativeScan.diagnostics;
        assert(!d.nativeScan.workerActive() && !diag.workerStarts);
        assert(diag.lastPlanFailure.reason == SequoiaWCL::ScanPlanReason::ChannelAbsent);
        assert(diag.lastPlanFailure.channel == 196 && diag.lastPlanFailure.channelIndex == 0);
        const auto failedRequest = diag.lastPlanFailureRequest;
        r.channelCount = 0;
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
        assert(diag.lastPlanFailureRequest == failedRequest && diag.planRejectCount == 1);
        assert(diag.acceptedRequest > failedRequest && diag.planReason == 0);
        dispatch(d.nativeScanCall); joined(d.nativeScanCall); d.deliver();
        assert(d.completion == 0);
        d.stop();
    }
    // The real net80211 state machine enters SCAN before an unassociated WCL
    // request. Regression check: SCAN is admitted, while AUTH/ASSOC remain
    // protected from racing a join transition.
    {
        AirportItlwm d;
        assert(d.initNativeScan());
        auto r = request();
        d.hal.ic.ic_state = IEEE80211_S_SCAN;
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
        dispatch(d.nativeScanCall); joined(d.nativeScanCall); d.deliver();
        assert(d.completion == 0);
        d.hal.ic.ic_state = IEEE80211_S_AUTH;
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnBusy);
        d.hal.ic.ic_state = IEEE80211_S_ASSOC;
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnBusy);
        d.stop();
    }
    for (unsigned failure = 1; failure <= 6; ++failure) {
        allocationStep = 0; allocationFailure = failure;
        AirportItlwm d; assert(!d.initNativeScan()); d.stop(); d.stop(); assert(!allocations);
    }
    allocationFailure = 0;
    for (unsigned scenario = 0; scenario < 12; ++scenario) {
        for (unsigned repeat = 0; repeat < 25; ++repeat) {
            AirportItlwm d; assert(d.initNativeScan()); auto r = request();
            if (scenario == 11) { r.scanType = 1; r.activeDwell = 40; }
            if (scenario == 0) { // Allocation of a timer deadline fails before acceptance.
                d.nativeScanTimer->failSchedule = true;
                assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnError);
                assert(d.references == 1 && !d.nativeScan.workerActive());
            } else {
                if (scenario == 3) d.hal.enableError = kIOReturnError;
                if (scenario == 4) d.hal.onEnable = [&] { d.cancelNativeScan(); };
                if (scenario == 5) d.hal.onEnable = [&] { d.pmOn = false; };
                if (scenario == 6 || scenario == 7 || scenario == 8) {
                    d.hal.onScan = [&] {
                        d.loop.commandWakeup(&d, false);
                        while (!d.hal.canceled) d.loop.commandSleep(&d, THREAD_UNINT);
                    };
                }
                assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
                assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnBusy);
                if (scenario == 1) { d.stop(); assert(d.hal.scans == 0); }
                else {
                    if (scenario == 2) d.loop.run([&] { return d.cancelNativeScan(); });
                    if (scenario == 9) d.loop.run([&] { d.pmOn = false; return 0; });
                    dispatch(d.nativeScanCall);
                    if (scenario == 6 || scenario == 7 || scenario == 8) {
                        d.loop.run([&] {
                            while (!d.hal.scans) d.loop.commandSleep(&d, THREAD_UNINT);
                            if (scenario == 8) {
                                d.loop.on = true;
                                assert(d.disableAdapter(d.bsdInterface) == kIOReturnCannotLock);
                                d.loop.on = false;
                                assert(!d.hal.canceled);
                                d.cancelNativeScan();
                            }
                            return 0;
                        });
                        if (scenario == 6) d.stop();
                        if (scenario == 7) {
                            d.hal.onDisable = [&] {
                                assert(d.nativeRadioTransition);
                                assert(d.requestNativeScan(&r) == kIOReturnNotReady);
                            };
                            apple80211_power_data off;
                            assert(d.setPOWER(nullptr, &off) == kIOReturnSuccess);
                            assert(d.power_state == 0 && !d.nativeRadioTransition);
                        }
                    }
                    if (scenario != 6) {
                        joined(d.nativeScanCall);
                        assert(d.references == 1 && !d.nativeScan.workerActive());
                        // The scan delivery's post step is the interface's own
                        // postMessage, which returns void and routes straight to
                        // IO80211Glue::routeEventToWcl. An injected post failure can
                        // therefore no longer be observed and retried, so scenario 10
                        // - whose only distinction was such an injection - drains like
                        // every other scenario.
                        d.deliver(); assert(d.posts == 1);
                        const bool success = scenario == 10 || scenario == 11;
                        assert(d.completion == (success ? 0u : 0xe3ff8100u));
                        if (scenario == 11) {
                            assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
                            joined(d.nativeScanCall); d.deliver(); assert(d.posts == 2 && d.completion == 0);
                        }
                    }
                }
            }
            d.stop(); d.stop(); assert(!allocations);
        }
    }
    for (unsigned repeat = 0; repeat < 100; ++repeat) {
        AirportItlwm d; assert(d.initNativeScan()); auto r = request();
        bool initializing = false, finishInit = false;
        d.hal.onEnable = [&] {
            initializing = true; d.loop.commandWakeup(&d, false);
            while (!finishInit) d.loop.commandSleep(&d, THREAD_UNINT);
        };
        std::thread enable([&] { assert(d.enableAdapter(d.bsdInterface) == kIOReturnNotReady); });
        d.loop.run([&] { while (!initializing) d.loop.commandSleep(&d, THREAD_UNINT); return 0; });
        std::thread powerOff([&] { d.loop.run([&] { d.setPowerStateOff(); return 0; }); });
        // Observe PM admission closure under its lock, then let initialization
        // return. No timeout/sleep is used to choose the race ordering.
        for (;;) {
            bool closed;
            { std::lock_guard<std::mutex> lock(d.pmMutex); closed = d.pmPowerState == kPowerStateOff; }
            if (closed) break;
            std::this_thread::yield();
        }
        d.loop.run([&] {
            assert(d.nativeRadioTransition && !d.policy.acks);
            assert(d.requestNativeScan(&r) == kIOReturnNotReady);
            finishInit = true; d.loop.commandWakeup(&d, false); return 0;
        });
        enable.join(); powerOff.join();
        assert(d.policy.acks == 1 && d.hal.disables == 1 && !d.nativeRadioTransition);
        apple80211_power_data state;
        assert(d.getPOWER(nullptr, &state) == kIOReturnSuccess && state.power_state[0] == 1);
        d.stop(); assert(!allocations);
    }
    for (unsigned repeat = 0; repeat < 100; ++repeat) {
        AirportItlwm d; assert(d.initNativeScan()); auto r = request();
        std::mutex mutex; std::condition_variable changed;
        bool atRelease = false, canRelease = false;
        d.beforeRelease = [&] {
            std::unique_lock<std::mutex> lock(mutex);
            atRelease = true; changed.notify_all();
            assert(changed.wait_for(lock, std::chrono::seconds(5), [&] { return canRelease; }));
        };
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
        dispatch(d.nativeScanCall);
        { std::unique_lock<std::mutex> lock(mutex);
          assert(changed.wait_for(lock, std::chrono::seconds(5), [&] { return atRelease; })); }
        d.deliver(); assert(d.completion == 0);
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
        auto *call = d.nativeScanCall->call;
        std::thread stop([&] { d.stop(); });
        { std::unique_lock<std::mutex> lock(call->mutex);
          assert(call->changed.wait_for(lock, std::chrono::seconds(5), [&] { return call->cancelWaitCalls == 1; }));
          assert(call->running && !call->pending); }
        { std::lock_guard<std::mutex> lock(mutex); canRelease = true; changed.notify_all(); }
        stop.join();
        assert(d.hal.scans == 1 && d.references == 1 && !allocations);
    }
    for (unsigned repeat = 0; repeat < 100; ++repeat) {
        AirportItlwm d;
        std::mutex mutex; std::condition_variable changed;
        bool atRelease = false, canRelease = false;
        d.beforeRelease = [&] {
            std::unique_lock<std::mutex> lock(mutex);
            atRelease = true; changed.notify_all();
            assert(changed.wait_for(lock, std::chrono::seconds(5), [&] { return canRelease; }));
        };
        auto *state = SequoiaThreadCall::allocate([](void *, void *) {}, &d);
        auto *call = state->call;
        if (repeat % 2) d.powerOffThreadCall = state;
        else d.powerOnThreadCall = state;
        assert(state->enter()); dispatch(call);
        { std::unique_lock<std::mutex> lock(mutex);
          assert(changed.wait_for(lock, std::chrono::seconds(5), [&] { return atRelease; })); }
        assert(state->enter());
        std::thread stop([&] { d.unregistPM(); });
        { std::unique_lock<std::mutex> lock(call->mutex);
          assert(call->changed.wait_for(lock, std::chrono::seconds(5), [&] { return call->cancelWaitCalls == 1; }));
          assert(call->running && !call->pending); }
        { std::lock_guard<std::mutex> lock(mutex); canRelease = true; changed.notify_all(); }
        stop.join(); d.stop();
        assert(!d.powerOffThreadCall && !d.powerOnThreadCall && d.references == 1);
    }
}

static SequoiaWCL::JoinRequest joinRequest()
{
    SequoiaWCL::JoinRequest r = {};
    r.ssidLength = 3; r.ssid[0] = 'a'; r.ssid[2] = 'b';
    r.candidateCount = 1; r.candidates[0].bssid[0] = 2;
    r.apMode = 2; r.unassociatedDwell = 120;
    r.controls1e4 = 2; r.controls3d4 = 20; r.controls3d8 = 5;
    return r;
}

template <typename Predicate>
static void awaitJoin(AirportItlwm &d, Predicate predicate)
{
    const auto limit = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    d.loop.run([&] {
        while (!predicate()) {
            assert(std::chrono::steady_clock::now() < limit);
            AbsoluteTime tick;
            clock_interval_to_deadline(10, kMillisecondScale, &tick);
            d.loop.commandSleep(&d.nativeJoin, tick, THREAD_UNINT);
        }
        return 0;
    });
}

static void joinTests()
{
    using namespace SequoiaWCL;
    for (unsigned failure = 1; failure <= 5; ++failure) {
        allocationStep = 0; allocationFailure = failure;
        AirportItlwm d; assert(!d.initNativeJoin()); d.stop(); d.stop();
    }
    allocationFailure = 0;
    for (unsigned repeat = 0; repeat < 10; ++repeat) {
        for (unsigned scenario = 0; scenario < 22; ++scenario) {
            testClock = 1000;
            AirportItlwm d;
            assert(d.initNativeJoin() && d.initNativeScan());
            auto r = joinRequest();
            d.hal.onJoin = [&] {
                assert(d.nativeJoin.request.get());
                ItlJoin::Event auth = {ItlJoin::Stage::Auth, {2,0,0,0,0,0}, 0};
                ItlJoin::Event assoc = {ItlJoin::Stage::Assoc, {2,0,0,0,0,0}, 0};
                if (scenario == 3) auth.status = 13;
                if (scenario == 4) assoc.status = 17;
                if (scenario != 5) assert(d.hal.nativeJoinProgress.record(auth, d.hal.com.sc_generation));
                if (scenario != 5 && scenario != 6 && scenario != 3)
                    assert(d.hal.nativeJoinProgress.record(assoc, d.hal.com.sc_generation));
                d.hal.portReady = scenario != 7;
                if (scenario == 8) ++d.hal.com.sc_generation;
                if (scenario == 9) d.hal.nativeStateError = EIO;
                if (scenario == 10) {
                    // The real fault task latches the HAL error and invalidates
                    // the session; the controller no longer reads raw IWM flags.
                    d.hal.com.sc_flags = IWM_FLAG_RFKILL;
                    d.hal.nativeStateError = ENETDOWN;
                    ++d.hal.com.sc_generation;
                }
                if (scenario == 21) d.hal.watchdogError = ETIMEDOUT;
            };
            if (scenario == 1) d.hal.enableError = kIOReturnError;
            if (scenario == 2) d.hal.joinError = EINVAL;
            if (scenario == 12) d.nativeJoinTimer->failSchedule = true;
            const auto accepted = d.loop.run([&] { return d.requestNativeJoin(&r); });
            if (scenario == 12) {
                assert(accepted == kIOReturnError && !d.nativeJoin.busy && !d.nativeJoin.request.get());
                d.stop(); continue;
            }
            assert(accepted == kIOReturnSuccess);
            r.ssid[0] = 'z';
            assert(d.loop.run([&] { return d.nativeJoin.request.get()->ssid[0]; }) == 'a');
            assert(d.loop.run([&] { return d.requestNativeJoin(&r); }) == kIOReturnBusy);
            auto scan = request();
            assert(d.loop.run([&] { return d.requestNativeScan(&scan); }) == kIOReturnBusy);
            assert(d.loop.run([&] { return d.enableAdapter(d.bsdInterface); }) == kIOReturnBusy);
            if (scenario == 13) {
                assert(d.loop.run([&] { return d.cancelNativeJoin(true); }) == 0);
                d.loop.run([&] { d.serviceNativeJoin(); assert(d.joinMessages.empty()); return 0; });
            }
            if (scenario == 14) { d.stop(); assert(d.hal.joins == 0); continue; }
            dispatch(d.nativeJoinCall);
            awaitJoin(d, [&] { return d.nativeJoin.started || !d.nativeJoin.worker; });
            d.loop.run([&] {
                assert(!d.nativeJoin.request.get());
                if (scenario == 21) d.nativeJoinTimerAction(&d, d.nativeJoinTimer);
                if (scenario >= 5 && scenario <= 7) testClock = 31000;
                if (scenario == 15) {
                    d.linkError = kIOReturnError;
                    d.nativeJoin.error = EIO;
                    d.serviceNativeJoin();
                }
                d.loop.commandWakeup(&d.nativeJoin, false);
                return 0;
            });
            if (scenario == 11) {
                assert(d.loop.run([&] { return d.disableAdapter(d.bsdInterface); }) == 0);
            }
            if (scenario == 16) {
                d.loop.run([&] {
                    d.nativeJoinTimer->failSchedule = true;
                    d.hal.portReady = false;
                    d.nativeJoinTimerAction(&d, d.nativeJoinTimer);
                    return 0;
                });
            }
            const bool success = scenario == 0 || (scenario >= 17 && scenario <= 20);
            if (success) {
                d.loop.run([&] {
                    d.postFailures = 2;
                    d.serviceNativeJoin(); d.serviceNativeJoin();
                    assert(d.joinMessages.empty() && !d.nativeJoin.connected);
                    d.hal.portReady = false;
                    d.serviceNativeJoin();
                    assert(d.joinMessages == std::vector<uint32_t>{kAssocEventMessage});
                    assert(!d.nativeJoin.connected && d.linkUps == 0);
                    d.hal.portReady = true; d.postFailures = 1;
                    d.serviceNativeJoin(); assert(!d.nativeJoin.connected && d.joinMessages.size() == 1);
                    d.completionFailures = 1;
                    d.serviceNativeJoin();
                    assert(d.linkEvents.size() == 1 && !d.nativeJoin.completionPosted && !d.linkUps);
                    d.serviceNativeJoin();
                    assert(d.linkEvents.size() == 1); // Retrying d5 must not duplicate d8.
                    assert(!d.nativeJoin.connected && d.nativeJoin.completionPosted && !d.linkUps);
                    LinkStateRequest link = {{2,0,0,0,0,0}, 1, 0, 1, {0xaa,0xaa,0xaa}, 0};
                    assert(d.requestNativeLink(nullptr) == kIOReturnBadArgument);
                    link.bssid[5] = 1;
                    assert(d.requestNativeLink(&link) == kIOReturnNotReady);
                    link.bssid[5] = 0; link.debounceCode = 1;
                    assert(d.requestNativeLink(&link) == kIOReturnUnsupported);
                    link.debounceCode = 0;
                    assert(d.requestNativeLink(&link) == 0 && !d.nativeJoin.connected && !d.linkUps);
                    link.publishInterface = 1; d.linkError = kIOReturnError;
                    assert(d.requestNativeLink(&link) == 0 && !d.nativeJoin.connected);
                    d.linkError = 0; d.serviceNativeJoin();
                    assert(d.nativeJoin.connected && d.nativeJoin.completionPosted);
                    assert(d.joinMessages == (std::vector<uint32_t>{kAssocEventMessage, kLinkStatusMessage, kConnectionCompleteMessage}));
                    // Replay Apple's audited state0/1 transitions. Completion
                    // without d8 is ignored; only d8 then d5 reaches state2.
                    const uint8_t net[2][2][2] = {{{1,2},{0,0}},{{1,2},{2,4}}};
                    unsigned state = 0, publications = 0;
                    assert(net[0][1][0] == 0 && net[0][1][1] == 0);
                    for (auto message : d.joinMessages) {
                        if (message == kAssocEventMessage) continue;
                        const auto event = message == kLinkStatusMessage ? 0 : 1;
                        const auto action = net[state][event][1];
                        state = net[state][event][0];
                        if (action == 4) ++publications;
                    }
                    assert(state == 2 && publications == 1);
                    assert(d.nativeJoin.diagnostics.completionStatus == 0);
                    assert(!d.lastJoinCompletion.ieeeStatus && !d.lastJoinCompletion.candidates[0].result.status);
                    return 0;
                });
                joined(d.nativeJoinCall);
                d.loop.run([&] {
                    if (scenario == 17) {
                        ItlJoin::Event deauth = {ItlJoin::Stage::Deauth, {2,0,0,0,0,0}, 3};
                        assert(d.hal.nativeJoinProgress.record(deauth, d.hal.com.sc_generation));
                        d.serviceNativeJoin();
                    } else if (scenario == 18) {
                        d.hal.com.sc_flags = IWM_FLAG_RFKILL; d.serviceNativeJoin();
                    } else if (scenario == 20) {
                        const auto polls = d.hal.watchdogPolls;
                        d.hal.watchdogError = ETIMEDOUT;
                        d.nativeJoinTimerAction(&d, d.nativeJoinTimer);
                        assert(d.hal.watchdogPolls == polls + 1 && d.nativeJoin.error == ETIMEDOUT);
                    } else {
                        if (scenario == 19) d.hal.onDisable = [&] {
                            d.hal.disableError = d.hal.disables < 3 ? kIOReturnBusy : 0;
                        };
                        assert(d.cancelNativeJoin(true) == 0);
                    }
                    assert(!d.nativeJoin.connected);
                    return 0;
                });
            }
            joined(d.nativeJoinCall);
            d.loop.run([&] {
                assert(d.nativeJoin.drained && !d.nativeJoin.worker && !d.nativeJoin.connected);
                d.linkError = 0; d.nativeJoinTimer->failSchedule = false;
                d.postFailures = 1;
                d.serviceNativeJoin();
                for (unsigned retry = 0; retry < 4 && d.nativeJoin.busy; ++retry) d.serviceNativeJoin();
                assert(!d.nativeJoin.busy && !d.nativeJoin.request.get());
                assert(d.nativeJoin.diagnostics.handshake.eapol.rxM1 == 17);
                if (scenario == 13) assert(d.joinMessages == std::vector<uint32_t>{kJoinAbortCompleteMessage});
                if (!success && scenario != 13) {
                    assert(d.joinMessages.back() == kConnectionCompleteMessage);
                    assert(d.lastJoinCompletion.ieeeStatus && d.lastJoinCompletion.candidates[0].result.status);
                }
                if (success) {
                    assert(d.linkEvents.size() == 2 && d.linkEvents[0].up == 1 && d.linkEvents[1].up == 0);
                    assert(d.nativeJoin.diagnostics.linkUpPosted && d.nativeJoin.diagnostics.linkDownPosted);
                } else assert(d.linkEvents.empty());
                if (scenario == 17 || scenario == 18 || scenario == 20) assert(d.joinMessages.size() == 4);
                assert(d.cancelNativeJoin(true) == 0);
                d.serviceNativeJoin();
                d.serviceNativeJoin();
                assert(!d.nativeJoin.busy && d.joinMessages.back() == kJoinAbortCompleteMessage);
                return 0;
            });
            d.stop(); assert(d.references == 1 && !allocations);
        }
    }
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        for (unsigned repeat = 0; repeat < 50; ++repeat) {
            AirportItlwm d; assert(d.initNativeJoin()); auto r = joinRequest();
            bool initializing = false, finishInit = false;
            d.hal.onEnable = [&] {
                initializing = true; d.loop.commandWakeup(&d, false);
                while (!finishInit) d.loop.commandSleep(&d, THREAD_UNINT);
            };
            assert(d.loop.run([&] { return d.requestNativeJoin(&r); }) == 0);
            dispatch(d.nativeJoinCall);
            awaitJoin(d, [&] { return initializing; });
            if (scenario == 0) {
                d.loop.run([&] {
                    assert(d.cancelNativeJoin(true) == 0);
                    d.serviceNativeJoin(); assert(d.joinMessages.empty());
                    finishInit = true; d.loop.commandWakeup(&d, false); return 0;
                });
                joined(d.nativeJoinCall);
                d.loop.run([&] { d.serviceNativeJoin(); assert(d.joinMessages == std::vector<uint32_t>{kJoinAbortCompleteMessage}); return 0; });
                d.stop();
            } else {
                std::thread closer([&] {
                    if (scenario == 1) assert(d.loop.run([&] { return d.disableAdapter(d.bsdInterface); }) == 0);
                    else d.stop();
                });
                awaitJoin(d, [&] { return d.nativeJoin.cancel; });
                d.loop.run([&] {
                    assert(d.nativeJoin.worker && !d.nativeJoin.drained && d.joinMessages.empty());
                    finishInit = true; d.loop.commandWakeup(&d, false); return 0;
                });
                closer.join();
                if (scenario == 1) d.stop();
            }
            assert(d.hal.joins == 0 && d.hal.disables && d.references == 1);
        }
    }
    // A previous callback can still hold its reference after clearing worker.
    // Canceling its queued successor must also join that old invocation.
    for (unsigned repeat = 0; repeat < 50; ++repeat) {
        AirportItlwm d; assert(d.initNativeJoin()); auto r = joinRequest();
        d.hal.enableError = kIOReturnError;
        std::mutex mutex; std::condition_variable changed;
        bool atRelease = false, canRelease = false;
        d.beforeRelease = [&] {
            std::unique_lock<std::mutex> lock(mutex);
            atRelease = true; changed.notify_all();
            assert(changed.wait_for(lock, std::chrono::seconds(5), [&] { return canRelease; }));
        };
        assert(d.loop.run([&] { return d.requestNativeJoin(&r); }) == 0);
        dispatch(d.nativeJoinCall);
        { std::unique_lock<std::mutex> lock(mutex);
          assert(changed.wait_for(lock, std::chrono::seconds(5), [&] { return atRelease; })); }
        d.loop.run([&] {
            d.serviceNativeJoin(); assert(!d.nativeJoin.busy);
            assert(d.requestNativeJoin(&r) == 0); return 0;
        });
        auto *call = d.nativeJoinCall->call;
        std::thread closer([&] { d.stop(); });
        { std::unique_lock<std::mutex> lock(call->mutex);
          assert(call->changed.wait_for(lock, std::chrono::seconds(5), [&] { return call->cancelWaitCalls == 1; }));
          assert(call->running && !call->pending); }
        { std::lock_guard<std::mutex> lock(mutex); canRelease = true; changed.notify_all(); }
        closer.join(); assert(d.hal.joins == 0 && d.references == 1);
    }
    // A background scan may still own the firmware when WCL synchronously
    // asks to leave. The production path must cancel and drain that scan
    // instead of returning Busy, then acknowledge its canceled completion so
    // an immediate next join is admitted.
    {
        AirportItlwm d;
        assert(d.initNativeJoin() && d.initNativeScan());
        auto scan = request();
        std::mutex mutex;
        std::condition_variable changed;
        bool entered = false;
        d.hal.onScan = [&] {
            {
                std::lock_guard<std::mutex> lock(mutex);
                entered = true;
                changed.notify_all();
            }
            d.loop.commandWakeup(&d, false);
            while (!d.hal.canceled) d.loop.commandSleep(&d.nativeScan, THREAD_UNINT);
        };
        assert(d.loop.run([&] { return d.requestNativeScan(&scan); }) == kIOReturnSuccess);
        std::thread dispatcher([&] {
            dispatch(d.nativeScanCall);
            joined(d.nativeScanCall);
        });
        {
            std::unique_lock<std::mutex> lock(mutex);
            assert(changed.wait_for(lock, std::chrono::seconds(5), [&] { return entered; }));
        }
        SequoiaWCL::LeaveRequest leave = {};
        leave.reason = 8;
        leave.waitMs = 30;
        assert(d.loop.run([&] { return d.requestNativeLeave(&leave); }) == kIOReturnSuccess);
        dispatcher.join();
        assert(!d.nativeScan.workerActive() && !d.nativeScan.delivery.busy());
        assert(d.hal.canceled && d.hal.scans == 1);
        assert(d.nativeJoin.diagnostics.leaveScanCanceled == 1 &&
               d.nativeJoin.diagnostics.leaveScanWaits == 1 &&
               d.nativeJoin.diagnostics.leaveStage == 12 &&
               d.nativeJoin.diagnostics.leaveFailures == 0);
        auto next = joinRequest();
        assert(d.loop.run([&] { return d.requestNativeJoin(&next); }) == kIOReturnSuccess);
        d.stop();
    }
    puts("Native scan preemption: synchronous leave cancels/drains a background scan and admits the next join");
    // WCL advances synchronously after LEAVE_NETWORK: no timer tick between
    // its return and MAC/candidate admission. Event and hardware failures must
    // retain the old owner until teardown can safely finish.
    for (unsigned fault = 0; fault < 9; ++fault) {
        AirportItlwm d; assert(d.initNativeJoin()); dispatch(d.nativeJoinCall);
        auto &j = d.nativeJoin;
        j.busy = j.started = j.associationReady = j.associationPosted = true;
        j.generation = d.hal.com.sc_generation;
        j.completion.candidates[0].bssid[0] = 2;
        assert(d.hal.nativeJoinProgress.begin(j.completion.candidates[0].bssid, j.generation));
        d.hal.portReady = true;
        d.loop.run([&] {
            if (fault) {
                j.linkRequested = true;
                d.serviceNativeJoin();
                assert(j.linkUpPosted && j.connected && j.completionPosted);
            } else j.connected = j.completionPosted = true;
            return 0;
        });
        if (fault == 2) d.postFailures = 1;
        if (fault == 3) d.linkError = kIOReturnError;
        if (fault == 4) d.hal.disableError = kIOReturnError;
        if (fault == 5) d.hal.leaveError = EIO;
        if (fault == 6) d.nativeJoinTimer->failSchedule = true;
        if (fault == 7) d.hal.onLeave = [&] { assert(d.cancelNativeJoin(true) == 0); };
        if (fault == 8) d.hal.onDisable = [&] { d.ready = false; };
        LeaveRequest leave = {};
        leave.reason = 8; leave.waitMs = 30; leave.bssid[0] = 2;
        const uint8_t nextMac[6] = {2, 7, 8, 9, 10, 11};
        auto next = joinRequest();
        d.loop.run([&] {
            const auto result = d.requestNativeLeave(&leave);
            const bool success = fault == 0 || fault == 1 || fault == 7;
            assert((result == kIOReturnSuccess) == success);
            const unsigned stage[] = {12, 12, 10, 9, 7, 11, 8, 12, 2};
            assert(j.diagnostics.leaveStage == stage[fault]);
            assert(j.diagnostics.leaveFailures == !success);
            if (!success) {
                assert(j.diagnostics.leaveLastFailureStage == stage[fault]);
                assert(j.diagnostics.leaveLastFailureRequest == 1);
            }
            if (fault == 2 || fault == 3 || fault == 4 || fault == 8) {
                assert(j.busy && d.linkEvents.size() == 1);
                assert(d.setHardwareAddress(nextMac, sizeof(nextMac)) != kIOReturnSuccess);
                assert(d.requestNativeJoin(&next) != kIOReturnSuccess);
                // Retry only after the original failure is removed. Failed
                // stop must really run again; no forced clear of busy/drained.
                d.ready = true; d.linkError = 0; d.hal.disableError = 0;
                d.hal.onDisable = nullptr;
                assert(d.requestNativeLeave(&leave) == kIOReturnSuccess);
                assert(j.diagnostics.leaveLastFailureStage == stage[fault]);
                assert(j.diagnostics.leaveLastFailureRequest == 1);
                assert(j.diagnostics.leaveFailures == 1);
            }
            d.nativeJoinTimer->failSchedule = false;
            assert(!j.busy && !j.worker);
            if (fault) {
                assert(d.linkEvents.size() == 2 && !d.linkEvents.back().up);
                assert(d.joinMessages.back() == (fault == 7 ? kJoinAbortCompleteMessage : kLinkStatusMessage));
            }
            const auto oldEvents = d.joinMessages.size();
            assert(d.setHardwareAddress(nextMac, sizeof(nextMac)) == kIOReturnSuccess);
            assert(d.requestNativeJoin(&next) == kIOReturnSuccess);
            // An old armed timer must not post another link-down into the new
            // session. The queued new worker cannot enter while we hold gate.
            d.serviceNativeJoin();
            assert(d.joinMessages.size() == oldEvents);
            return 0;
        });
        d.stop();
    }
    puts("Synchronous leave handoff: immediate MAC/join, ordered old link-down, enqueue/publication/stop/TX/timer/lifecycle failures, abort race and retained failure diagnostics passed");
    for (unsigned scenario = 0; scenario < 12; ++scenario) {
        for (unsigned repeat = 0; repeat < 10; ++repeat) {
            AirportItlwm d; assert(d.initNativeJoin()); dispatch(d.nativeJoinCall);
            auto &join = d.nativeJoin;
            join.busy = join.started = join.connected = join.completionPosted = true;
            join.associationReady = join.associationPosted = true;
            join.generation = d.hal.com.sc_generation;
            join.completion.candidates[0].bssid[0] = 2;
            assert(d.hal.nativeJoinProgress.begin(join.completion.candidates[0].bssid, join.generation));
            LeaveRequest request = {};
            request.reason = 3; request.deauthenticate = scenario % 2; request.waitMs = 100;
            request.bssid[0] = 2;
            d.hal.portReady = true;
            if (scenario == 1) request.reason = 0;
            if (scenario == 2) request.reason = UINT32_MAX;
            if (scenario == 3) request.enhancedReason = 1;
            if (scenario == 4) request.waitMs = 1001;
            if (scenario == 5) request.bssid[5] = 1;
            if (scenario == 6) d.nativeRadioTransition = true;
            if (scenario == 7) request.deauthenticate = 2;
            if (scenario == 8) d.loop.on = true;
            if (scenario == 9) d.hal.leaveError = EIO;
            if (scenario == 10) d.hal.onLeave = [&] {
                d.hal.leaveError = d.hal.leaves < 3 ? EBUSY : 0;
            };
            const auto result = d.loop.run([&] { return d.requestNativeLeave(&request); });
            d.loop.on = false; d.nativeRadioTransition = false;
            if (scenario > 0 && scenario < 9) {
                assert(result != kIOReturnSuccess && !d.hal.leaves && !d.hal.disables && join.connected);
            } else {
                joined(d.nativeJoinCall);
                assert((result == kIOReturnSuccess) == (scenario != 9));
                assert(d.hal.leaves && d.hal.disables && join.diagnostics.leaveDrained && !join.busy && !join.worker && !join.connected);
                d.loop.run([&] { d.serviceNativeJoin(); assert(!join.busy && d.joinMessages.empty()); return 0; });
                assert(d.loop.run([&] { return d.requestNativeLeave(&request); }) == 0);
            }
            d.stop();
        }
    }
    // Link indication accepted, but completion never queued: expiry/cancel
    // must balance d8 and keep the data gate shut, including failed down mail.
    for (unsigned abort = 0; abort < 2; ++abort) {
        AirportItlwm d; assert(d.initNativeJoin());
        d.loop.run([&] {
            auto &j = d.nativeJoin;
            j.busy = j.started = j.associationReady = j.associationPosted = true;
            j.generation = d.hal.com.sc_generation;
            j.completion.candidates[0].bssid[0] = 2;
            assert(d.hal.nativeJoinProgress.begin(j.completion.candidates[0].bssid, j.generation));
            d.hal.portReady = true; d.completionFailures = 1;
            d.serviceNativeJoin();
            assert(j.linkUpPosted && !j.completionPosted && !j.connected && !d.linkUps);
            j.error = ETIMEDOUT; j.abort = abort; j.drained = true;
            j.failureCompletion();
            d.postFailures = 1; d.serviceNativeJoin();
            assert(j.busy && !j.linkDownPosted && d.linkEvents.size() == 1);
            d.serviceNativeJoin();
            assert(!j.busy && !j.connected && !d.linkUps);
            assert(d.linkEvents.size() == 2 && !d.linkEvents.back().up);
            assert(d.joinMessages.back() == (abort ? kJoinAbortCompleteMessage : kConnectionCompleteMessage));
            if (!abort) assert(j.diagnostics.completionStatus == 1);
            return 0;
        });
        d.stop();
    }
    puts("Native WCL link handoff: audited event ordering, key gate, duplicate-free retry, metadata-only request and balanced teardown passed; WCL consumer mocked");
    puts("Native join owner: 5 allocation failures, 220 fault traces including watchdog expiry, 150 init-abort/PM/stop races and 50 pending-plus-running teardown races passed; hardware mocked");
    puts("Native normal leave: 120 synchronous stop/rejection/firmware-busy/TX-failure/idle traces passed; HAL notification mocked");
    for (unsigned fault = 0; fault < 12; ++fault) {
        AirportItlwm d;
        auto &join = d.nativeJoin;
        join.busy = join.started = join.completionPosted = true;
        d.hal.portReady = true;
        if (fault == 1) d.ready = false;
        if (fault == 2) join.busy = false;
        if (fault == 3) join.started = false;
        if (fault == 4) join.cancel = true;
        if (fault == 5) join.error = EIO;
        if (fault == 6) join.drained = true;
        if (fault == 7) join.completionPosted = false;
        if (fault == 8) d.hal.portReady = false;
        if (fault == 9) d.hal.nativeStateError = EIO;
        if (fault == 10) d.nativeRadioTransition = true;
        if (fault == 11) d.hal.com.sc_flags = IWM_FLAG_RFKILL;
        assert(d.finishNativeLinkConfiguration() == kIOReturnCannotLock);
        const auto result = d.loop.run([&] { return d.finishNativeLinkConfiguration(); });
        assert((result == kIOReturnSuccess) == (fault == 0));
        assert(!join.connected && !d.linkUps && d.joinMessages.empty());
        if (!fault) assert(d.loop.run([&] { return d.finishNativeLinkConfiguration(); }) == 0);
    }
    puts("Native link-up-done: 12 actual admission/power-readiness traces and idempotence passed; no early traffic publication");
}

static void publicThreadCallTests()
{
    allocationFailure = 0;
    for (unsigned repeat = 0; repeat < 100; ++repeat) {
        AirportItlwm d;
        auto *state = SequoiaThreadCall::allocate([](void *, void *) { assert(false); }, &d);
        assert(state && state->enter());
        for (unsigned n = 0; n < 10; ++n) assert(state->enter());
        assert(d.references == 2 && state->outstanding == 1);
        assert(state->closeAndWait() && d.references == 1);
        assert(!state->enter() && !state->closeAndWait());
        SequoiaThreadCall::destroy(state);
        assert(!state && !allocations);
    }
    for (unsigned repeat = 0; repeat < 100; ++repeat) {
        AirportItlwm d;
        auto *state = SequoiaThreadCall::allocate([](void *, void *) { assert(false); }, &d);
        assert(state && state->enter());
        std::thread producer1([&] { for (unsigned n = 0; n < 100; ++n) state->enter(); });
        std::thread producer2([&] { for (unsigned n = 0; n < 100; ++n) state->enter(); });
        assert(state->closeAndWait());
        producer1.join(); producer2.join();
        assert(d.references == 1 && !state->outstanding && !state->enter());
        SequoiaThreadCall::destroy(state);
        assert(!state && !allocations);
    }
    puts("Public ONCE threadcall wrapper: 100 coalescing/cancellation/closed-admission and 100 concurrent submission/shutdown traces passed; kernel scheduling mocked");
}

AirportItlwm *IONetworkInterface::owner = nullptr;

void IONetworkInterface::postMessage(uint32_t kind, void *data, size_t size, bool dispatch)
{
    assert(owner);
    owner->postMessage(this, kind, data, size, dispatch);
}

// The scan timer and the airportd-completion path hand the glue's queued events to
// the WCL right after posting them. The fixture has no glue, so count the calls: a
// delivery pass that never fetches its events leaves the WCL's handlers with
// nothing to run, which is exactly what r168 measured on hardware.
static int glueScheduleCalls = 0;
bool itlwmGlueScheduleEvents(void *)
{
    ++glueScheduleCalls;
    return true;
}
bool itlwmGlueWakeState(void *, void **gate, unsigned *wake)
{
    if (gate) *gate = nullptr;
    if (wake) *wake = 0;
    return true;
}

static void macTests()
{
    const uint8_t original[6] = {0x88,1,2,3,4,5};
    const uint8_t privateMac[6] = {2,7,8,9,10,11};
    for (unsigned fault = 0; fault < 13; ++fault) {
        AirportItlwm d;
        SequoiaWCL::ScanDelivery::Slot pending;
        IOReturn expected = kIOReturnSuccess;
        switch (fault) {
            case 1: d.ready = false; expected = kIOReturnNotReady; break;
            case 2: d.pmOn = false; expected = kIOReturnNotReady; break;
            case 3: d.power_state = 0; expected = kIOReturnNotReady; break;
            case 4: d.nativeRadioTransition = true; expected = kIOReturnNotReady; break;
            case 5: d.nativeJoin.busy = true; expected = kIOReturnBusy; break;
            case 6:
                assert(d.nativeScan.delivery.setStorage(&pending, 1));
                assert(d.nativeScan.delivery.begin(ItlScan::Firmware::LMAC));
                expected = kIOReturnBusy; break;
            case 7: d.loop.on = true; expected = kIOReturnCannotLock; break;
            case 8: d.hal.disableError = kIOReturnBusy; expected = kIOReturnBusy; break;
            case 9: d.hal.disableError = kIOReturnError; expected = kIOReturnError; break;
            case 10: d.hal.onDisable = [&] { d.ready = false; }; expected = kIOReturnNotReady; break;
            case 11: d.hal.onDisable = [&] { d.pmPowerState = kPowerStateOff; }; expected = kIOReturnNotReady; break;
            case 12: d.bsdInterface = nullptr; expected = kIOReturnNotReady; break;
        }
        assert(d.setHardwareAddress(privateMac, 6) == expected);
        const auto *wanted = fault ? original : privateMac;
        assert(!memcmp(d.hal.ic.ic_myaddr, wanted, 6));
        assert(!memcmp(d.hal.ic.ic_ac.ac_enaddr, wanted, 6));
        assert(d.nativeMacChanges == (fault ? 0u : 1u));
        assert(d.nativeRadioTransition == (fault == 4));
        if (!fault) {
            assert(d.hal.disables == 1 && !d.hal.enables);
            d.nativeJoin.busy = true;
            assert(d.setHardwareAddress(privateMac, 6) == kIOReturnSuccess);
            assert(d.hal.disables == 1); // Idempotence must not interrupt join.
            d.nativeJoin.busy = false;
            assert(d.setHardwareAddress(original, 6) == kIOReturnSuccess);
            assert(d.hal.disables == 2 && d.nativeMacChanges == 2);
        }
    }
    AirportItlwm d;
    uint8_t invalid[6] = {};
    assert(d.setHardwareAddress(nullptr, 6) == kIOReturnBadArgument);
    for (unsigned length : {0u,1u,5u,7u,UINT32_MAX})
        assert(d.setHardwareAddress(privateMac, length) == kIOReturnBadArgument);
    assert(d.setHardwareAddress(invalid, 6) == kIOReturnBadArgument);
    invalid[0] = 1;
    assert(d.setHardwareAddress(invalid, 6) == kIOReturnBadArgument);
    assert(!d.hal.disables && !d.nativeMacChanges);
    d.hal.onDisable = [&] {
        assert(d.nativeRadioTransition);
        assert(!d.nativeRadioAvailable());
        assert(d.setHardwareAddress(original, 6) == kIOReturnNotReady);
    };
    assert(d.setHardwareAddress(privateMac, 6) == kIOReturnSuccess);
    // Model firmware releasing the gate while stopping. Full controller stop
    // must wait for that callback, even after it has closed ready admission.
    for (unsigned repeat = 0; repeat < 20; ++repeat) {
        AirportItlwm owner;
        bool entered = false, drainEntered = false, release = false;
        std::atomic<bool> drained{false};
        owner.hal.onDisable = [&] {
            entered = true; owner.loop.commandWakeup(&entered, false);
            while (!release) owner.loop.commandSleep(&release, THREAD_UNINT);
        };
        std::thread setter([&] {
            assert(owner.setHardwareAddress(privateMac, 6) == kIOReturnNotReady);
        });
        owner.loop.run([&] {
            while (!entered) owner.loop.commandSleep(&entered, THREAD_UNINT);
            owner.ready = false;
            return 0;
        });
        std::thread stopper([&] {
            owner.loop.run([&] {
                drainEntered = true; owner.loop.commandWakeup(&drainEntered, false);
                owner.drainNativeRadioTransition();
                drained = true;
                return 0;
            });
        });
        owner.loop.run([&] {
            while (!drainEntered) owner.loop.commandSleep(&drainEntered, THREAD_UNINT);
            assert(!drained && owner.nativeRadioTransition);
            release = true; owner.loop.commandWakeup(&release, false);
            return 0;
        });
        setter.join(); stopper.join();
        assert(drained && !owner.nativeMacChanges);
        assert(!memcmp(owner.hal.ic.ic_myaddr, original, 6));
    }
    puts("Native MAC: invalid inputs, idempotence, restore, busy/stop/PM failures and transition exclusion passed; HAL mocked");
}

namespace {
uint32_t directCalls = 0, directLastMsgId = 0, directResult = 0;
bool directSucceeds = true;
bool fakeWclDirectRoute(void *, uint32_t msgId, void *, size_t, uint32_t *result)
{
    ++directCalls;
    directLastMsgId = msgId;
    if (result) *result = directResult;
    return directSucceeds;
}
} // namespace

// r223/d149 installed the direct WCL route into a function-scope pointer that
// shadowed the one the delivery reads, so a whole boot silently used the
// interface queue (ItlwmNativeWclDirectPosts=0 with 124 queue posts). The install
// now goes through itlwmSetWclDirectPostRoute; pin all three behaviours so the
// mistake cannot recur unnoticed: an installed route replaces the queue post, a
// rejecting route falls back and retains its first failure code, and no route at
// all keeps the queue behaviour.
static void directRouteTests()
{
    for (unsigned mode = 0; mode < 3; ++mode) {
        AirportItlwm d;
        assert(d.initNativeScan());
        directCalls = directLastMsgId = 0;
        // Every installed route resolves the chain; a rejecting route is modelled
        // by its non-zero handler result, which the delivery counts as a failure
        // and then falls back to the interface queue (the board never committed
        // the rejected payload).
        directSucceeds = true;
        directResult = mode == 1 ? 0xe00002bc : 0;
        itlwmSetWclDirectPostRoute(mode == 2 ? nullptr : fakeWclDirectRoute);
        auto r = request();
        assert(d.loop.run([&] { return d.requestNativeScan(&r); }) == kIOReturnSuccess);
        dispatch(d.nativeScanCall); joined(d.nativeScanCall); d.deliver();
        const auto &diag = d.nativeScan.diagnostics;
        if (mode == 2) {
            assert(!directCalls && !diag.wclDirectPosts && !diag.wclDirectFailures);
            assert(d.posts > 0 && diag.lastResultMsgIndex ==
                   ((SequoiaWCL::kScanCompleteMessage << 16) | SequoiaWCL::kScanResultMsgType));
        } else {
            assert(directCalls > 0);
            assert(diag.wclDirectPosts + diag.wclDirectFailures == directCalls);
            if (mode == 0) {
                assert(diag.wclDirectPosts == directCalls && !diag.wclDirectFailures);
                assert(!d.posts && diag.wclDirectLastResult == 0);
                assert(diag.wclDirectFirstFailure == UINT32_MAX);
                assert(diag.lastResultMsgIndex ==
                       ((directLastMsgId << 16) | SequoiaWCL::kScanResultMsgType));
            } else {
                assert(!diag.wclDirectPosts && diag.wclDirectFailures == directCalls);
                assert(diag.wclDirectLastResult == 0xe00002bc);
                assert(diag.wclDirectFirstFailure == 0xe00002bc);
                assert(d.posts == directCalls);
            }
        }
        itlwmSetWclDirectPostRoute(nullptr);
        d.stop();
    }
}

static void wakeTests() {
    for(unsigned scenario=0;scenario<9;++scenario) {
        AirportItlwm d;assert(d.initNativeScan());assert(d.initNativeJoin());
        d.pmPowerState=kPowerStateOff;
        d.power_state=scenario==1?0:1;
        d.wakeRetries=77; // Each wake reports its own retry count, including no-op.
        if(scenario==2) d.ready=false;
        if(scenario==3) d.hal.transportReady=false;
        if(scenario==4) d.nativeJoin.busy=true; // No premature reset of an undrained join.
        if(scenario==5) d.hal.enableError=kIOReturnError;
        if(scenario>=6) {
            d.nativeJoin.busy=true;d.nativeJoin.cancel=true;d.nativeJoin.drained=true;
            d.nativeJoin.completionPosted=true;d.nativeJoin.linkUpPosted=true;
            if(scenario==7) d.postFailures=1;
            if(scenario==8) d.postFailures=1000;
        }
        unsigned before=d.hal.enables;
        d.loop.run([&] { d.setPowerStateOn();return 0; });
        assert(d.pmPowerState==kPowerStateOn && d.policy.acks==1);
        assert(d.power_state==(scenario==1?0u:1u));
        assert(d.hal.enables-before==(scenario==0 || scenario==3 || scenario==5 || scenario==6 || scenario==7 ? 1u:0u));
        if(scenario==4 || scenario==8) assert(d.nativeJoin.busy);
        if(scenario==6 || scenario==7) assert(!d.nativeJoin.busy);
        const uint32_t expected=scenario==4 || scenario==8 ? kIOReturnBusy :
            scenario==5 ? kIOReturnError : kIOReturnSuccess;
        assert(d.wakeError==expected);
        assert(d.wakeRetries==(scenario==7?1u:scenario==8?100u:0u));
        d.ready=true;d.nativeJoin.reset();d.stop();assert(!allocations);
    }
    // The bounded wait releases the gate. A newer stop/radio/PM request wins;
    // a join that is no longer drained must never be forcibly reset.
    for (unsigned change=0;change<4;++change) {
        AirportItlwm d;assert(d.initNativeScan());assert(d.initNativeJoin());
        d.pmPowerState=kPowerStateOff;
        d.nativeJoin.busy=true;d.nativeJoin.cancel=true;d.nativeJoin.drained=true;
        d.nativeJoin.completionPosted=true;d.nativeJoin.linkUpPosted=true;
        d.postFailures=1000;
        d.loop.onTimedSleep=[&] {
            if(change==0) d.ready=false;
            if(change==1) d.power_state=0;
            if(change==2) d.pmPowerState=kPowerStateOff;
            if(change==3) d.nativeJoin.drained=false;
        };
        d.loop.run([&] {d.setPowerStateOn();return 0;});
        assert(d.policy.acks==1 && d.hal.enables==0 && d.wakeRetries==1);
        assert(d.wakeError==(change==3?kIOReturnBusy:kIOReturnNotReady));
        assert(d.nativeJoin.busy);
        d.loop.onTimedSleep=nullptr;d.ready=true;d.nativeJoin.reset();
        d.stop();assert(!allocations);
    }
    for(unsigned repeat=0;repeat<20;++repeat) {
        AirportItlwm d;assert(d.initNativeScan());
        d.pmPowerState=kPowerStateOff;
        bool started=false,finish=false;
        d.hal.onEnable=[&] {
            started=true;d.loop.commandWakeup(&d,false);
            while(!finish) d.loop.commandSleep(&d,THREAD_UNINT);
        };
        std::thread wake([&] { d.loop.run([&] {d.setPowerStateOn();return 0;}); });
        d.loop.run([&] {
            while(!started) d.loop.commandSleep(&d,THREAD_UNINT);
            assert(d.nativeRadioTransition && d.policy.acks==0);
            d.ready=false;finish=true;d.loop.commandWakeup(&d,false);return 0;
        });
        wake.join();
        assert(d.policy.acks==1 && d.wakeError==kIOReturnNotReady && !d.nativeRadioTransition);
        d.stop();assert(!allocations);
    }
    puts("PM wake: 9 restore/backpressure cases, 4 superseding requests and 20 stop races passed; bounded retries preserve undrained join and radio-off preference; firmware mocked");
}

int main()
{
    wakeTests();
    // An already-on radio must accept a duplicate power-on even while a join
    // session owns the controller. No firmware reinitialization is needed.
    for (unsigned fault = 0; fault < 7; ++fault) {
        AirportItlwm d;
        d.nativeSkywalkBSDOwner = true; d.bsdInterface = nullptr;
        d.power_state = 1; d.nativeFirmwareAnnounced = true;
        d.nativeJoin.busy = true; d.nativeJoin.connected = true;
        d.hal.ic.ic_if.if_flags = IFF_RUNNING;
        if (fault == 1) d.power_state = 0;
        if (fault == 2) d.hal.ic.ic_if.if_flags = 0;
        if (fault == 3) d.hal.transportReady = false;
        if (fault == 4) d.hal.nativeStateError = EIO;
        if (fault == 5) d.hal.detached = true;
        if (fault == 6) d.pmOn = false;
        apple80211_power_data on; on.power_state[0] = 1;
        const auto result = d.setPOWER(nullptr, &on);
        assert((result == kIOReturnSuccess) == (fault == 0));
        assert(d.hal.enables == 0 && d.hal.disables == 0 && d.nativeJoin.connected);
        apple80211_power_data read;
        assert(d.getPOWER(nullptr, &read) == kIOReturnSuccess);
        assert(read.power_state[0] == (fault == 1 ? 0u : 1u));
    }

    // Skywalk owns the BSD ifnet; there is deliberately no custom legacy child.
    for (unsigned fault = 0; fault < 6; ++fault) {
        AirportItlwm d;
        d.nativeSkywalkBSDOwner = true;
        d.bsdInterface = nullptr;
        d.power_state = 0;
        apple80211_power_data on, off;
        on.power_state[0] = 1;
        if (fault == 1) d.fNetIf = nullptr;
        if (fault == 2) d.interface.bsdAttached = false;
        if (fault == 3) d.hal.enableError = kIOReturnError;
        if (fault == 4) d.pmOn = false;
        if (fault == 5) d.hal.onEnable = [&] { d.ready = false; };
        const auto result = d.setPOWER(nullptr, &on);
        assert((result == kIOReturnSuccess) == !fault);
        assert(d.power_state == !fault && d.nativeFirmwareAnnounced == !fault);
        if (!fault) {
            const uint8_t address[6] = {2,7,8,9,10,11};
            assert(d.setHardwareAddress(address, 6) == kIOReturnSuccess);
            assert(!memcmp(d.hal.ic.ic_myaddr, address, 6));
            d.hal.disableError = kIOReturnError;
            assert(d.setPOWER(nullptr, &off) == kIOReturnError && d.power_state == 1);
            d.hal.disableError = 0;
            d.interface.bsdAttached = false; // Lost client must not block power-off.
            assert(d.setPOWER(nullptr, &off) == kIOReturnSuccess && d.power_state == 0);
        }
    }
    {
        AirportItlwm d;
        apple80211_power_data on;
        on.power_state[0] = 1;
        d.power_state = 0;
        d.hal.enableError = kIOReturnError;
        assert(d.setPOWER(nullptr, &on) == kIOReturnError);
        assert(!d.nativeFirmwareAnnounced && !d.firmwareAnnouncements && !d.power_state);
        d.hal.enableError = 0;
        d.postFailures = 1;
        assert(d.setPOWER(nullptr, &on) == kIOReturnSuccess);
        assert(!d.nativeFirmwareAnnounced && !d.firmwareAnnouncements);
        assert(d.setPOWER(nullptr, &on) == kIOReturnSuccess);
        assert(d.nativeFirmwareAnnounced && d.firmwareAnnouncements == 1);
        assert(d.setPOWER(nullptr, &on) == kIOReturnSuccess);
        apple80211_power_data off;
        assert(d.setPOWER(nullptr, &off) == kIOReturnSuccess);
        assert(d.setPOWER(nullptr, &on) == kIOReturnSuccess);
        assert(d.firmwareAnnouncements == 1);
        puts("Firmware-ready: actual setPOWER success/failure, copied payload, retry and idempotence passed");
    }
    for (unsigned fault = 0; fault < 7; ++fault) {
        AirportItlwm d;
        d.nativeSkywalkBSDOwner = true;
        d.bsdInterface = nullptr;
        AirportItlwmSkywalkInterface callback{&d};
        ether_addr address{{2,7,8,9,10,11}};
        const uint8_t original[6] = {0x88,1,2,3,4,5};
        if (fault == 1) callback.instance = nullptr;
        if (fault == 2) d.interface.bsdAttached = false;
        if (fault == 3) d.power_state = 0;
        if (fault == 4) d.nativeJoin.busy = true;
        if (fault == 5) d.hal.disableError = kIOReturnError;
        if (fault == 6) address.octet[0] = 1;
        const auto expected = !fault ? kIOReturnSuccess :
            fault <= 3 ? kIOReturnNotReady : fault == 4 ? kIOReturnBusy :
            fault == 5 ? kIOReturnError : kIOReturnBadArgument;
        assert(callback.setMacAddress(address) == expected);
        assert(!memcmp(d.hal.ic.ic_myaddr, fault ? original : address.octet, 6));
        assert(!memcmp(d.hal.ic.ic_ac.ac_enaddr, fault ? original : address.octet, 6));
        assert(d.nativeMacChanges == !fault);
        if (!fault) {
            assert(callback.setMacAddress(address) == kIOReturnSuccess);
            assert(d.nativeMacChanges == 1 && d.hal.disables == 1);
        }
    }
    puts("Actual Skywalk MAC callback: no legacy child, missing owner/ifnet, power, busy, HAL failure, invalid address and idempotence passed");
    macTests();
    routeTests();
    directRouteTests();
    publicThreadCallTests();
    tests();
    assocScanTests();
    assert(glueScheduleCalls > 0);
    joinTests();
    puts("Native scan controller: 6 allocation failures, 300 scan traces, 3 direct-route install/fallback cases, 100 PM-init, 100 scan-shutdown and 100 PM-shutdown races, associated-scan gate/health/Q9 readback passed");
}
