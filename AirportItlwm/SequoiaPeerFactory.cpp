// Native ABI bridges, re-audited against 24H23 during host migration.
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <Airport/SequoiaInterfaceLifecycle.h>
#include <Airport/SequoiaPeerDiagnostics.h>

#if __IO80211_TARGET >= __MAC_15_0
extern "C" OSObject *ccReporter(OSObject *, IOWorkLoop *)
    __asm("__ZN15CCFaultReporter18withStreamWorkloopEP12CCDataStreamP10IOWorkLoop");
extern "C" bool ccAttach(OSObject *, IOService *)
    __asm("__ZN15CCFaultReporter6attachEP9IOService");
extern "C" void ccDetach(OSObject *, IOService *)
    __asm("__ZN15CCFaultReporter6detachEP9IOService");
extern "C" OSObject *faultAdapter(OSObject *)
    __asm("__ZN20IO80211FaultReporter15allocWithParamsEP15CCFaultReporter");
extern "C" bool peerInit(OSObject *, void *, void *)
    __asm("__ZN18IO80211PeerManager17initWithInterfaceEP23IO80211VirtualInterfaceP23IO80211SkywalkInterface");
extern "C" void peerFreeResources(OSObject *)
    __asm("__ZN18IO80211PeerManager13freeResourcesEv");
extern "C" unsigned queueDepth(void *)
    __asm("__ZN23IO80211SkywalkInterface17getDataQueueDepthEv");
extern "C" const char *bsdName(void *)
    __asm("__ZN23IO80211SkywalkInterface10getBSDNameEv");

extern "C" void *io80211GlueWithInterface(void *)
    __asm("__ZN11IO80211Glue11withOptionsEP23IO80211SkywalkInterface");

using SequoiaInterfaceLifecycle::read;

// The interface's glue ivar at +0xd8. IO80211SkywalkInterface::postMessageInternal
// loads it and jumps to IO80211Glue::routeEventToWcl when it is set, and falls back to
// postMessageSync when it is null - so a null glue would mean no driver event reaches
// the WCL no matter which message id or route the delivery uses, which is exactly what
// four consecutive candidates looked like. Read it before trusting any of that.
void *itlwmInterfaceGlue(void *interface)
{
    if (!interface) return nullptr;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return nullptr;
    return read<void *>(ivars, 0xd8);
}

// Install the glue the family's own factory builds, at the ivar its own
// postMessageInternal reads. Returns through installed the glue that is in place
// afterwards, whether it was already there or was just created.
bool itlwmEnsureInterfaceGlue(void *interface, void **installed)
{
    if (installed) *installed = nullptr;
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (glue) {
        if (installed) *installed = glue;
        return true;
    }
    glue = io80211GlueWithInterface(interface);
    if (!glue) return false;
    *reinterpret_cast<void **>(static_cast<uint8_t *>(ivars) + 0xd8) = glue;
    if (installed) *installed = glue;
    return true;
}

// The r214 boot proved the glue object itself is built but its WCLBulletinBoard is
// not: WCLGlue::receiveMessageInternal reads glue ivars+0x8 as the board and drops
// every scan-result message when it is null, and r214 read it as 0. WCLGlue::
// initWithOptions builds that board through WCLBulletinBoard::withOptions, whose
// first action is a base-class init (vtable slot read through a global function
// table) that returned false. That init belongs to the IOReporter family and runs
// against a not-yet-registered controller while the driver builds the glue during
// interface start, before its own registerService. Rebuild the glue after the
// controller is published: if the board is still missing, the base init gets a
// second, post-registration attempt; otherwise the existing glue is left untouched.
bool itlwmRebuildInterfaceGlue(void *interface, void **installed)
{
    if (installed) *installed = nullptr;
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (glue) {
        void *glueIvars = read<void *>(glue, 0x18);
        void *bulletin = glueIvars ? read<void *>(glueIvars, 0x8) : nullptr;
        if (bulletin) {
            if (installed) *installed = glue;
            return true;
        }
        // The board is still null: the base init failed during the pre-registration
        // attempt. Detach the broken glue and build a fresh one now that the
        // controller service is visible.
        *reinterpret_cast<void **>(static_cast<uint8_t *>(ivars) + 0xd8) = nullptr;
        reinterpret_cast<OSObject *>(glue)->release();
    }
    glue = io80211GlueWithInterface(interface);
    if (!glue) return false;
    *reinterpret_cast<void **>(static_cast<uint8_t *>(ivars) + 0xd8) = glue;
    if (installed) *installed = glue;
    return true;
}

// 24H232 WCLBulletinBoard::initWithOptions reads its base vtable global
// at 0xffffff800211fe2f + 7 + 0x29c2da, then calls *0x98(%rax).
// -- the base class's init, reached through a global vtable-pointer slot at link
// address 0xffffff80023bc110. r215 proved that call returns false both before and
// after controller registration, so the failing init cannot be OSObject::init (which
// unconditionally returns true). Read the real runtime function pointer through the
// slide computed from IO80211Glue::withOptions so the next boot can name the init.
void itlwmReadWclBulletinBoardBaseInit(uint64_t *table, uint64_t *slot98)
{
    if (table) *table = 0;
    if (slot98) *slot98 = 0;
    const uintptr_t anchorLink = 0xffffff800212b2d4ULL;  // 24H232 IO80211Glue::withOptions
    const uintptr_t globalLink = 0xffffff80023be110ULL;  // base vtable pointer slot
    const int64_t slide = static_cast<int64_t>(
        reinterpret_cast<uintptr_t>(&io80211GlueWithInterface)) - static_cast<int64_t>(anchorLink);
    void *tbl = *reinterpret_cast<void **>(static_cast<uintptr_t>(globalLink) + slide);
    if (table) *table = reinterpret_cast<uint64_t>(tbl);
    if (tbl && slot98)
        *slot98 = reinterpret_cast<uint64_t>(
            *reinterpret_cast<void **>(reinterpret_cast<uint8_t *>(tbl) + 0x98));
}

// The r168-r216 deliveries were read through the wrong chain: glue ivars+0x8 ->
// +0x120 -> +0xb08 is the event-delivery path IO80211Glue::receiveMessageInternal
// walks, not the WCLGlue storage. IO80211Glue::initWithOptions stores the WCLGlue
// it builds at ivars+0x18, and WCLGlue stores its WCLBulletinBoard at its own
// ivars+0x8. Read that correct chain so the board and its scan-result bitmap are
// finally observed at their real location.
bool itlwmGlueBulletinBoardCorrect(void *interface, void **board, uint8_t *bytes, size_t len)
{
    if (board) *board = nullptr;
    if (bytes && len) memset(bytes, 0, len);
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return false;
    void *glueIvars = read<void *>(glue, 0x18);
    if (!glueIvars) return false;
    void *wclGlue = read<void *>(glueIvars, 0x18);   // WCLGlue lives here, not +0x8
    if (!wclGlue) return false;
    void *wclIvars = read<void *>(wclGlue, 0x18);
    if (!wclIvars) return false;
    void *bulletin = read<void *>(wclIvars, 0x8);
    if (board) *board = bulletin;
    if (!bulletin) return false;
    uint8_t *bitmaps = read<uint8_t *>(bulletin, 0x10);
    if (!bitmaps) return false;
    if (bytes && len) memcpy(bytes, bitmaps + 0x8d0, len);
    return true;
}

// Read the WCL controller chain built by WCLGlue::initWcl: WCLGlue ivars+0x0 is the
// WCLController, and WCLController ivars+0x28 is the WCLScanManager (which inherits
// WCLFsmManager). r217 showed the scan-message bitmap is 0 even though
// gSCAN_MANAGERCallBackArray contains those messages, so either the controller or the
// scan manager was never built, or the FSM's setMessageEnable loop never ran.
bool itlwmReadWclControllerChain(void *interface, void **controller, void **scanManager)
{
    if (controller) *controller = nullptr;
    if (scanManager) *scanManager = nullptr;
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return false;
    void *glueIvars = read<void *>(glue, 0x18);
    if (!glueIvars) return false;
    void *wclGlue = read<void *>(glueIvars, 0x18);
    if (!wclGlue) return false;
    void *wclIvars = read<void *>(wclGlue, 0x18);
    if (!wclIvars) return false;
    void *ctrl = read<void *>(wclIvars, 0x0);
    if (controller) *controller = ctrl;
    if (!ctrl) return false;
    void *ctrlIvars = read<void *>(ctrl, 0x10);
    if (!ctrlIvars) return false;
    void *scan = read<void *>(ctrlIvars, 0x28);
    if (scanManager) *scanManager = scan;
    return scan != nullptr;
}

// Q9 readback: the entry count of the WCL scan cache's IO80211Queue. The chain
// is exactly what 24G830's WCLScanManager::getCachedBeacons walks (0x2795e):
//
//     scanManager+0x20 -> +0x68 (IO80211ScanCacheStore) -> +0x10 -> +0x00 (queue)
//
// and queueEnqueue/queueDequeue keep the count at *(queue+0x10)+0x08 as a 32-bit
// atomic (storage+0x00 capacity, +0x10 lock, +0x18 list head), verified against
// the KDK disassembly. Only counters and pointers leave this helper; no SSID,
// BSSID or frame bytes are read.
bool itlwmReadWclCacheQueueCount(void *interface, uint64_t *count, void **cacheStore, void **queue)
{
    if (count) *count = 0;
    if (cacheStore) *cacheStore = nullptr;
    if (queue) *queue = nullptr;
    void *scanManager = nullptr;
    if (!itlwmReadWclControllerChain(interface, nullptr, &scanManager)) return false;
    void *hop = read<void *>(scanManager, 0x20);
    if (!hop) return false;
    void *store = read<void *>(hop, 0x68);
    if (cacheStore) *cacheStore = store;
    if (!store) return false;
    void *inner = read<void *>(store, 0x10);
    if (!inner) return false;
    void *scanQueue = read<void *>(inner, 0x00);
    if (queue) *queue = scanQueue;
    if (!scanQueue) return false;
    void *storage = read<void *>(scanQueue, 0x10);
    if (!storage) return false;
    if (count) *count = read<uint32_t>(storage, 0x08);
    return true;
}

extern "C" void itlwmSetMessageEnable(void *board, uint32_t managerId, uint32_t msgIndex, bool enable)
    __asm("__ZN16WCLBulletinBoard16setMessageEnableE25WCLBulletinBoardManagerId24WCLBulletinBoardMsgIndexb");

extern "C" uint32_t itlwmWclBoardSendMessage(void *board, uint32_t managerId, void *message)
    __asm("__ZN16WCLBulletinBoard11sendMessageE25WCLBulletinBoardManagerIdR20bulletinBoardMessage");

// Direct WCL scan delivery. 24G830's own route for a driver-posted scan message is
// IO80211SkywalkInterface::postMessage -> routeEventToWcl -> addEventToPendingQueue
// -> sendEventAndFilter, which builds a FRESH CommonGlueMessage {+0x00 kind,
// +0x04 msgType 0, +0x08 size, +0x10 payload} and hands it to
// WCLGlue::receiveMessageInternal (0x12f70). That function computes the bulletin
// index itself - msgIndex = (kind << 16) | 2, because the msgType byte is 0 - and
// then calls WCLBulletinBoard::sendMessage(board, 12, msg) with the board at
// WCLGlue ivars+0x18 -> +0x8. This helper makes the identical call directly, for
// one reason: sendMessage returns the first non-zero handler result (routeMsg
// accumulates it), while the queue route only stores that verdict in its own
// message's +0x28 result byte, which this driver can never read back. The r223
// note claiming the queue hands WCLGlue a stale pre-allocated message is refuted
// by sendEventAndFilter's stack construction; the queue path is functional and
// remains the fallback when this chain does not resolve.
struct ItlwmBulletinBoardMessage {
    uint32_t msgIndex;    // +0x00 (msgId << 16) | msgType
    uint32_t filler;      // +0x04 Apple leaves 0xAAAAAAAA here; nothing reads it
    uint64_t length;      // +0x08
    void *data;           // +0x10
    uint64_t field18;     // +0x18
    uint64_t field20;     // +0x20
    uint8_t result;       // +0x28 handler return flag
    uint8_t pad29[7];
};
static_assert(sizeof(ItlwmBulletinBoardMessage) == 0x30, "bulletinBoardMessage size");

bool itlwmPostWclScanResult(void *interface, uint32_t msgId, void *bytes, size_t size,
                             uint32_t *lastResult)
{
    if (lastResult) *lastResult = UINT32_MAX;
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return false;
    void *glueIvars = read<void *>(glue, 0x18);
    if (!glueIvars) return false;
    void *wclGlue = read<void *>(glueIvars, 0x18);
    if (!wclGlue) return false;
    void *wclIvars = read<void *>(wclGlue, 0x18);
    if (!wclIvars) return false;
    void *board = read<void *>(wclIvars, 0x8);
    if (!board) return false;
    ItlwmBulletinBoardMessage message = {};
    message.msgIndex = (msgId << 16) | 2;  // scan family: msgType 2
    message.filler = 0xAAAAAAAAu;
    message.length = size;
    message.data = bytes;
    // True means the board was reached and sendMessage ran; *result carries its
    // return, which routeMsg fills with the first non-zero handler result. False
    // is reserved for an unresolvable chain, so the caller can fall back to the
    // interface queue only when nothing was actually delivered.
    if (lastResult) *lastResult = itlwmWclBoardSendMessage(board, 12 /* manager id */, &message);
    return true;
}

// gSCAN_MANAGERCallBackArray's first four entries are the scan-result messages
// (msgId 0xc9/0xcd/0xce/0xed, msgType 2), and WCLFsmManager::initWithOptions is
// supposed to enable them through setMessageEnable. r217 read those bits as 0, so
// enable them directly on the board to unblock the result delivery.
bool itlwmEnableScanMessages(void *interface)
{
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return false;
    void *glueIvars = read<void *>(glue, 0x18);
    if (!glueIvars) return false;
    void *wclGlue = read<void *>(glueIvars, 0x18);
    if (!wclGlue) return false;
    void *wclIvars = read<void *>(wclGlue, 0x18);
    if (!wclIvars) return false;
    void *bulletin = read<void *>(wclIvars, 0x8);
    if (!bulletin) return false;
    const uint32_t scanIndexes[] = {0xc90002u, 0xcd0002u, 0xce0002u, 0xed0002u};
    for (uint32_t idx : scanIndexes)
        itlwmSetMessageEnable(bulletin, 6 /* scan manager */, idx, true);
    return true;
}

// r222: callMsgCallBack resolves a message through a msgIndex -> handler dispatch
// table at WCLFsmManager ivars+0x10 (count at +0x18), each entry 0x18 bytes of
// {msgIndex(4B), fn(8B), offset(8B)}. msgIndex encodes (msgId<<16)|msgType, so the
// scan-result messages are 0xc90002 (0xc9) and 0xce0002 (0xce). If neither is in the
// table, every scan-result message is dropped with E00002BC - exactly the "FSM events
// 0" symptom. Dump the table so one boot shows which msgIndexes are registered and
// their handler pointers: this separates "registration never added the scan ids" from
// "the handler was registered but drops the message".
bool itlwmDumpScanManagerHandlers(void *interface, uint64_t *count,
                                  uint32_t *indexes, void **handlers, size_t maxEntries)
{
    if (count) *count = 0;
    if (indexes) for (size_t i = 0; i < maxEntries; ++i) indexes[i] = 0;
    if (handlers) for (size_t i = 0; i < maxEntries; ++i) handlers[i] = nullptr;
    if (!interface) return false;
    void *ctrl = nullptr, *scan = nullptr;
    if (!itlwmReadWclControllerChain(interface, &ctrl, &scan)) return false;
    // WCLScanManager inherits WCLFsmManager; the FSM ivars live at +0x18.
    void *fsmIvars = read<void *>(scan, 0x18);
    if (!fsmIvars) return false;
    uint64_t n = read<uint64_t>(fsmIvars, 0x18);
    if (count) *count = n;
    void *table = read<void *>(fsmIvars, 0x10);
    if (!table) return false;
    size_t lim = n < static_cast<uint64_t>(maxEntries) ? static_cast<size_t>(n) : maxEntries;
    for (size_t i = 0; i < lim; ++i) {
        if (indexes) indexes[i] = read<uint32_t>(table, i * 0x18);
        if (handlers) handlers[i] = read<void *>(table, i * 0x18 + 0x8);
    }
    return true;
}

// r228 A: read back the live state of a Skywalk packet queue so one boot shows
// whether the kernel's netif nexus ever attached it. IOSkywalkPacketQueue::
// initialize (+0x298095a) sets the initialized byte (+0xcc) exactly once, and
// IOSkywalkRxCompletionQueue::enqueuePackets (+0x29a36b6) refuses every packet
// with 0xE00002D7 while +0x28 (the IOEventSource enabled byte) or +0xcc is
// clear, and with 0xE00002D8 while +0x30 is null - that field is the
// IOEventSource workLoop, not a packet table. It then branches on +0x78, which
// selects the networking path over the KPipe path, so a queue that initializes
// with +0x78 == 0 still cannot hand a frame to the BSD stack. +0xbc counts the
// initialize calls and +0xe0 records the argument the nexus callback passed.
// Returns the enqueue admission verdict so the caller can publish/log it once.
bool itlwmPublishQueueState(IOService *target, const char *prefix, void *queue)
{
    if (!target || !prefix || !queue) return false;
    struct QueueField {
        const char *suffix;
        uint32_t offset;
        unsigned width;
    };
    static const QueueField fields[] = {
        {"Enabled", 0x28, 8},      // IOEventSource::enabled; 0 -> E00002D7
        {"WorkLoop", 0x30, 64},    // IOEventSource workLoop; null -> E00002D8
        {"Pool", 0x50, 64},
        {"NetifRoute", 0x78, 64},  // non-zero -> enqueuePacketsForNetworking
        {"QueueSet", 0x80, 64},
        {"Key", 0x98, 64},
        {"Id", 0xa0, 64},
        {"Limit", 0xac, 32},
        {"InitCount", 0xbc, 32},
        {"Initialized", 0xcc, 8},  // set by IOSkywalkPacketQueue::initialize
        {"Suspend", 0x118, 32},
        {"InitArg", 0xe0, 64},
        {"State124", 0x124, 32},
    };
    char key[96];
    for (const QueueField &field : fields) {
        strlcpy(key, prefix, sizeof(key));
        strlcat(key, field.suffix, sizeof(key));
        const uint64_t value = field.width == 8  ? read<uint8_t>(queue, field.offset)
                             : field.width == 32 ? read<uint32_t>(queue, field.offset)
                                                 : read<uint64_t>(queue, field.offset);
        target->setProperty(key, value, field.width);
    }
    // The exact admission test enqueuePackets performs before it accepts anything.
    const bool ready = read<uint8_t>(queue, 0x28) == 1 &&
                       read<uint8_t>(queue, 0xcc) == 1 &&
                       read<uint64_t>(queue, 0x30) != 0;
    strlcpy(key, prefix, sizeof(key));
    strlcat(key, "Ready", sizeof(key));
    target->setProperty(key, ready);
    // Networking branch. A ready queue with this still zero accepts packets but
    // never delivers them to the BSD stack.
    strlcpy(key, prefix, sizeof(key));
    strlcat(key, "BSDStack", sizeof(key));
    target->setProperty(key, read<uint64_t>(queue, 0x78) != 0);
    return ready;
}

// r228 A: IOSkywalkFamily declares an IOKit personality for
// IOSkywalkNetworkBSDClient (IOProviderClass=IOSkywalkNetworkInterface,
// IOResourceMatch=IOBSD, IOProbeScore 1000) and no other kext allocates that
// class, so IOKit itself instantiates and starts the client once the interface
// is published - the driver never calls it. Whether the client is present, and
// how far its start got, is the other half of the "queue never initialized"
// question: the kernel netif nexus hands this client to nxp_qset_init as the
// nexus context (kern_nexus_get_context), and that callback reads the client's
// ifnet (+0xf8, written by gatedPrepareNexus) to initialize the queue set.
// Walk the interface's service-plane children, publish their class names, and
// publish the client's own fields when it is there.
bool itlwmPublishInterfaceChildren(IOService *target, void *interface, unsigned *count)
{
    if (count) *count = 0;
    if (!target || !interface) return false;
    auto *service = static_cast<IORegistryEntry *>(interface);
    OSIterator *children = service->getChildIterator(gIOServicePlane);
    if (!children) return false;
    constexpr unsigned maxChildren = 8;
    unsigned seen = 0;
    bool clientFound = false;
    for (IORegistryEntry *child = nullptr;
         (child = static_cast<IORegistryEntry *>(children->getNextObject())) != nullptr; ) {
        const OSMetaClass *meta = child->getMetaClass();
        const char *name = meta ? meta->getClassName() : nullptr;
        if (!name) continue;
        if (seen < maxChildren) {
            char key[64];
            strlcpy(key, "ItlwmNativeChild", sizeof(key));
            const char digit[2] = {static_cast<char>('0' + seen), '\0'};
            strlcat(key, digit, sizeof(key));
            target->setProperty(key, name);
        }
        ++seen;
        if (strcmp(name, "IOSkywalkNetworkBSDClient") != 0) continue;
        clientFound = true;
        // start()'s own fields: +0xe8 the interface, +0xf0 the RegistrationInfo,
        // +0xf8 the ifnet gatedPrepareNexus stored, +0xd0 the nexus instance the
        // kernel returned, +0xb8 the nexus controller. +0x144 is set as start's
        // last step and +0x28 is the service's enabled byte.
        target->setProperty("ItlwmNativeBsdClient",
                            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(child)), 64);
        target->setProperty("ItlwmNativeBsdClientInterface",
                            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(read<void *>(child, 0xe8))), 64);
        target->setProperty("ItlwmNativeBsdClientInfo",
                            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(read<void *>(child, 0xf0))), 64);
        target->setProperty("ItlwmNativeBsdClientIfnet",
                            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(read<void *>(child, 0xf8))), 64);
        target->setProperty("ItlwmNativeBsdClientNexus",
                            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(read<void *>(child, 0xd0))), 64);
        target->setProperty("ItlwmNativeBsdClientController",
                            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(read<void *>(child, 0xb8))), 64);
        const uint32_t state = (read<uint8_t>(child, 0x144) ? 1u : 0u) |
                               (read<uint8_t>(child, 0x28) ? 2u : 0u);
        target->setProperty("ItlwmNativeBsdClientState", state, 32);
    }
    children->release();
    if (count) *count = seen;
    target->setProperty("ItlwmNativeChildCount", seen, 32);
    target->setProperty("ItlwmNativeBsdClientPresent", clientFound);
    return clientFound;
}

// getManagerMsgBitmap returns ivars + 0x8d0 + msgId*2: each message id owns a 16-bit
// bitmap at a 2-byte stride. The r213/r217 ScanMsgBits read of bytes 25..29 wrongly
// assumed a 1-byte stride, so it never saw msgId 0xc9/0xcd/0xce/0xed. Read the real
// words plus the block flag (ivars+0xc00) that isMsgNeeded checks first.
void itlwmReadScanBitmapCorrect(void *interface, uint16_t *out, unsigned *blockFlag)
{
    if (out) for (int i = 0; i < 4; ++i) out[i] = 0;
    if (blockFlag) *blockFlag = 0;
    if (!interface) return;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return;
    void *glueIvars = read<void *>(glue, 0x18);
    if (!glueIvars) return;
    void *wclGlue = read<void *>(glueIvars, 0x18);
    if (!wclGlue) return;
    void *wclIvars = read<void *>(wclGlue, 0x18);
    if (!wclIvars) return;
    void *bulletin = read<void *>(wclIvars, 0x8);
    if (!bulletin) return;
    void *bivars = read<void *>(bulletin, 0x10);
    if (!bivars) return;
    if (blockFlag) *blockFlag = read<uint8_t>(bivars, 0xc00);
    if (out) {
        const uint32_t ids[] = {0xc9, 0xcd, 0xce, 0xed};
        for (int i = 0; i < 4; ++i)
            out[i] = read<uint16_t>(bivars, 0x8d0 + ids[i] * 2);
    }
}

// Ask the glue's own event source to process its pending queue. The family
// creates that source in initWithOptions and binds it to ivars+0x38
// (fMainWorkQueue). Calling the raw drain synchronously from the driver's
// workloop bypasses that serialization and can race the WCL queue worker.
extern "C" void itlwm_glue_process_pending_events_source(void *glue, void *workQueue)
    __asm("__ZN11IO80211Glue30processPendingEventQueueSourceEP16IO80211WorkQueue");

bool itlwmGlueScheduleEvents(void *interface)
{
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return false;
    void *glueIvars = read<void *>(glue, 0x18);
    if (!glueIvars) return false;
    void *workQueue = read<void *>(glueIvars, 0x38);
    if (!workQueue) return false;
    itlwm_glue_process_pending_events_source(glue, workQueue);
    return true;
}

// The two links routeEventToWcl touches besides the queue itself: the gate at
// glue+0x18 and the wake byte at gate+0x30, which it sets only when that byte was
// still clear. Reading them shows whether anything has consumed the queue since
// the driver began posting.
bool itlwmGlueWakeState(void *interface, void **gate, unsigned *wake)
{
    if (gate) *gate = nullptr;
    if (wake) *wake = 0;
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return false;
    void *gateway = read<void *>(glue, 0x18);
    if (gate) *gate = gateway;
    if (!gateway) return false;
    if (wake) *wake = read<uint8_t>(gateway, 0x30);
    return true;
}

// The chain IO80211Controller::postMessage walks before anything reaches the WCL:
//
//     movq 0x120(%rdi), %rax      ; controller ivars + 0x10
//     movq 0xb08(%rax), %rdi      ; the family's delivery object
//     movq (%rdi), %rax
//     jmpq *0x120(%rax)           ; -> IO80211Glue::routeEventToWcl
//
// The controller this driver passes is its own AirportItlwm, whose ivars pointer
// lives at +0x110, so the two loads are ivars+0x10 and that object +0xb08. The
// r167 boot posted 181 completions and 3082 result beacons while the family's scan
// FSM logged only 29 SCAN_COMPLETE events and never a single SCAN_RESULT, so most
// deliveries - which all report success - are not arriving. Reading the chain
// separates "there is nowhere to deliver" from "the delivery arrives and is
// dropped", which is the difference between fixing the route and fixing the
// message.
bool itlwmControllerDeliveryChain(void *controller, void **first, void **second)
{
    if (first) *first = nullptr;
    if (second) *second = nullptr;
    if (!controller) return false;
    void *ivars = read<void *>(controller, 0x110);
    if (!ivars) return false;
    void *gate = read<void *>(ivars, 0x10);
    if (first) *first = gate;
    if (!gate) return false;
    void *delivery = read<void *>(gate, 0xb08);
    if (second) *second = delivery;
    return delivery != nullptr;
}

// IO80211Glue::receiveMessageInternal - the vtable-0x120 slot that
// sendEventAndFilter dispatches each queued event through - walks this chain to
// reach the WCL's scan callbacks:
//
//     movq 0x18(%rdi), %rdx      ; glue ivars
//     movq 0x8(%rdx),  %rdi      ; ivars+0x8   -> object A
//     movq 0x120(%rdi),%rsi      ; objectA+0x120 -> object B
//     movq 0xb08(%rsi),%rdi      ; objectB+0xb08 -> delivery object
//     callq *0x120(%rdi vtable)  ; -> gSCAN_MANAGERCallBackArray
//
// On r211 the scan requests are all admitted and 74 result messages are posted,
// the glue's pending-event queue and worker are in place, and yet
// scanupdateHandler never runs. Reading this chain separates "the delivery object
// was never built" from "it was built but drops the message", which is the
// difference between fixing the glue wiring and fixing the WCL callback array.
bool itlwmGlueDeliveryChain(void *interface, void **objectA, void **objectB, void **delivery)
{
    if (objectA) *objectA = nullptr;
    if (objectB) *objectB = nullptr;
    if (delivery) *delivery = nullptr;
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return false;
    void *glueIvars = read<void *>(glue, 0x18);
    if (!glueIvars) return false;
    void *a = read<void *>(glueIvars, 0x8);
    if (objectA) *objectA = a;
    if (!a) return false;
    void *b = read<void *>(a, 0x120);
    if (objectB) *objectB = b;
    if (!b) return false;
    void *del = read<void *>(b, 0xb08);
    if (delivery) *delivery = del;
    return del != nullptr;
}

// One hop past itlwmGlueDeliveryChain. The delivery object is a WCLGlue whose
// receiveMessageInternal reads ivars+0x8 as the WCLBulletinBoard and calls
// WCLBulletinBoard::sendMessage. That, in turn, calls getManagerMsgBitmap(msgType,
// id), which reads the bitmap array at board+0x10 and, for msgType 2 (scan
// results), the bytes at offset 0x8d0; the message id selects a bit there. The r213
// boot posted 74 results and scanupdateHandler never ran, which is what an unset
// bitmap bit looks like. Read the bytes so the next boot shows whether the
// scan-result ids (0xc9/0xcd/0xce/0xed -> bytes 25..29) are set.
bool itlwmGlueMsgBitmap(void *interface, void **board, uint8_t *bytes, size_t len)
{
    if (board) *board = nullptr;
    if (bytes && len) memset(bytes, 0, len);
    if (!interface) return false;
    void *ivars = read<void *>(interface, 0x110);
    if (!ivars) return false;
    void *glue = read<void *>(ivars, 0xd8);
    if (!glue) return false;
    void *glueIvars = read<void *>(glue, 0x18);
    if (!glueIvars) return false;
    void *a = read<void *>(glueIvars, 0x8);
    if (!a) return false;
    void *b = read<void *>(a, 0x120);
    if (!b) return false;
    void *wclGlue = read<void *>(b, 0xb08);
    if (!wclGlue) return false;
    void *wclIvars = read<void *>(wclGlue, 0x18);
    if (!wclIvars) return false;
    void *bulletin = read<void *>(wclIvars, 0x8);
    if (board) *board = bulletin;
    if (!bulletin) return false;
    uint8_t *bitmaps = read<uint8_t *>(bulletin, 0x10);
    if (!bitmaps) return false;
    if (bytes && len) memcpy(bytes, bitmaps + 0x8d0, len);
    return true;
}

OSObject *itlwmCreateFaultAdapter(IOService *stream, IOWorkLoop *loop, OSObject **reporter)
{
    if (!reporter) return nullptr;
    *reporter = nullptr;
    // Slot 0x120 in CCStream is copyProperty, not registerCallbacks!
    if (!stream || !stream->metaCast("CCDataStream") || !loop) return nullptr;
    OSObject *raw = ccReporter(stream, loop);
    if (!raw) return nullptr;
    OSObject *adapter = faultAdapter(raw); // Retains the raw reporter.
    if (!adapter) {
        raw->release();
        return nullptr;
    }
    *reporter = raw; // Allocation reference retained for explicit shutdown.
    return adapter;
}

bool itlwmAttachFaultReporter(OSObject *reporter, IOService *controller)
{
    // IOService attachment is to the controller, after family start. The data
    // stream is retained internally by withStreamWorkloop, not the provider.
    return reporter && controller && reporter->metaCast("CCFaultReporter") &&
        ccAttach(reporter, controller);
}

void itlwmReleaseFaultAdapter(OSObject **adapter, OSObject **reporter, IOService *attachedController)
{
    if (!adapter || !reporter) return;
    // Stop callbacks before detaching the SAME controller used by attach.
    // CCFaultReporter::free owns its timer/stream/workloop cleanup; do not
    // call freeResources twice or confuse its stream stop with detach.
    if (*reporter && attachedController) ccDetach(*reporter, attachedController);
    OSSafeReleaseNULL(*adapter);
    OSSafeReleaseNULL(*reporter);
}

static void number(OSDictionary *dict, const char *key, uint64_t value)
{
    auto *n = OSNumber::withNumber(value, 64);
    if (n) { dict->setObject(key, n); n->release(); }
}

bool itlwmFaultAdapterInstalled(IOService *controller, OSObject *adapter)
{
    return controller && adapter && adapter->metaCast("IO80211FaultReporter") &&
        read<void *>(read<void *>(controller, 0x120), 0x58) == adapter;
}

static void word(OSDictionary *dict, const char *key, const char *value)
{
    auto *s = OSString::withCString(value);
    if (s) { dict->setObject(key, s); s->release(); }
}

// Read before release. These are observations, not invented Apple error codes.
static const struct { const char *name; size_t offset; } peerFields[] = {
    {"controller", 0x518}, {"logger", 0xc08}, {"recursive_lock", 0x78},
    {"command_gate", 0x510}, {"command_queue_0", 0x4f0},
    {"command_queue_1", 0x4f8}, {"command_queue_2", 0x500},
    {"command_queue_3", 0x508}, {"broadcast_peer", 0x520},
    {"data_timer", 0x710}, {"primary_interface", 0x548},
    {"virtual_interface", 0x550}, {"null_address_peer", 0x528},
    {"virtual_peer_queue", 0x530}, {"virtual_aux_queue", 0x748},
    {"pending_queue", 0x750}, {"completion_queue", 0x758},
    {"infra_database", 0xb28}, {"timesync_database", 0xb30},
    {"monitor_timer", 0x708}, {"unflow_timer", 0x6f8},
    {"p2p_manager", 0}, {"stopwatch", 0x5b0}, {"fault_adapter", 0x8b8},
    {"sysctl_net_llreach", 0x768}, {"optional_lock", 0x618}
};

static const char *failureBoundary(const void *ivars, uint32_t interfaceId)
{
    if (!ivars) return "manager-ivars-allocation-or-base-init";
    if (!read<void *>(ivars, 0x78)) return "recursive-lock-allocation";
    if (!read<void *>(ivars, 0x510)) return "command-gate-allocation";
    for (size_t off = 0x4f0; off <= 0x508; off += 8)
        if (!read<void *>(ivars, off)) return "command-queue-allocation-or-capacity";
    if (!read<void *>(ivars, 0x710)) return "data-timer-allocation";
    if (!read<void *>(ivars, 0x528)) return "primary-null-address-peer";
    if (!read<void *>(ivars, 0x750) || !read<void *>(ivars, 0x758)) return "pending-or-completion-queue";
    if (interfaceId == 0 && !read<void *>(ivars, 0xb28)) return "infra-database";
    if ((interfaceId == 0 || interfaceId == 2 || interfaceId == 3) &&
        !read<void *>(ivars, 0xb30)) return "timesync-database";
    if (!read<void *>(ivars, 0x708)) return "monitor-timer-allocation";
    if (!read<void *>(ivars, 0x6f8)) return "unflow-timer-allocation";
    if (!read<void *>(ivars, 0)) return "p2p-manager-allocation";
    if (!read<uint8_t>(ivars, 0x6b9)) return "addAllEventSource-interface-workqueue";
    if (!read<void *>(ivars, 0x5b0)) return "stopwatch";
    if (!read<void *>(ivars, 0x768)) return "net-llreach-sysctl";
    if (!read<void *>(ivars, 0x8b8)) return "fault-adapter";
    return "after-fault-callbacks";
}

void *itlwmCreatePeerWithDiagnostics(IOService *interface, IOService *controller,
                                   IOService *evidence, IOWorkLoop *loop)
{
    if (!interface || !controller || !evidence || !loop) return nullptr;
    const void *iface = read<void *>(interface, 0x110);
    const void *ctrl = read<void *>(controller, 0x120);
    auto *adapter = read<OSObject *>(ctrl, 0x58);
    auto *history = OSArray::withCapacity(1);
    auto *preflight = OSDictionary::withCapacity(16);
    if (!history || !preflight) {
        OSSafeReleaseNULL(history); OSSafeReleaseNULL(preflight);
        evidence->setProperty("ItlwmNativePeerFailure", "diagnostic-allocation");
        return nullptr;
    }
    // Called from the family's real createPeerManager slot AFTER start has
    // retained controller/workqueue and created the logger, never beforehand.
    const uint32_t role = read<uint32_t>(iface, 0x58);
    const uint32_t interfaceId = read<uint32_t>(iface, 0x5c);
    const bool adapterValid = adapter && adapter->metaCast("IO80211FaultReporter");
    const char *name = iface ? bsdName(interface) : nullptr;
    number(preflight, "controller_matches", read<void *>(iface, 0x30) == controller);
    number(preflight, "interface_workqueue_matches", read<void *>(iface, 0x38) == loop);
    number(preflight, "role", read<uint32_t>(iface, 0x58));
    number(preflight, "interface_id", read<uint32_t>(iface, 0x5c));
    number(preflight, "interface_logger", reinterpret_cast<uintptr_t>(read<void *>(iface, 0x78)));
    number(preflight, "fault_adapter_valid", adapterValid);
    number(preflight, "peer_slot_empty", !read<void *>(iface, 0x28));
    number(preflight, "parent_slot_empty", !read<void *>(iface, 0x68));
    word(preflight, "bsd_name", name ? name : "");
    // 24G830 getBSDName returns its own empty buffer until a real ifnet exists;
    // the initializer uses it for logging/rvi boot-args, not as an admission gate.
    number(preflight, "bsd_name_pending", name && !name[0]);
    const bool safe = read<void *>(iface, 0x30) == controller &&
        read<void *>(iface, 0x38) == loop && adapterValid && role == 1 && interfaceId == 1 &&
        name && read<void *>(iface, 0x78) && !read<void *>(iface, 0x28) &&
        !read<void *>(iface, 0x68);
    if (!safe) {
        evidence->setProperty("ItlwmNativePeerPreflight", preflight);
        evidence->setProperty("ItlwmNativePeerFailure", "interface-or-fault-adapter-precondition");
        preflight->release(); history->release();
        return nullptr;
    }
    const unsigned depth = queueDepth(interface);
    number(preflight, "queue_depth", depth);
    // Observe the real input only. Capacity probes would mutate/allocate Apple
    // queue state and are not an independent, side-effect-free parameter test.
    evidence->setProperty("ItlwmNativePeerPreflight", preflight);
    preflight->release();
    if (!depth || depth > 0xffff) {
        evidence->setProperty("ItlwmNativePeerFailure", "invalid-queue-depth");
        history->release();
        return nullptr;
    }

    void *result = nullptr;
    {
        // Primary is Apple's normal (nullptr, this) contract. A failed private
        // initializer is not permission to change its object role or re-enter it.
        // All independent preconditions above are collected in one snapshot.
        auto *record = OSDictionary::withCapacity(32);
        if (!record) { history->release(); return nullptr; }
        word(record, "mode", "primary");
        evidence->setProperty("ItlwmNativePeerFailure", "initializer-in-progress");
        auto *manager = OSMetaClass::allocClassWithName("IO80211PeerManager");
        bool ok = manager && peerInit(manager, nullptr, interface);
        const void *ivars = manager ? read<void *>(manager, 0x18) : nullptr;
        number(record, "base_ivars", manager && read<void *>(manager, 0x10));
        number(record, "init_returned_true", ok);
        for (const auto &field : peerFields)
            number(record, field.name, reinterpret_cast<uintptr_t>(read<void *>(ivars, field.offset)));
        number(record, "event_sources_ready", read<uint8_t>(ivars, 0x6b9));
        const char *boundary = ok ? "complete" : (manager ? failureBoundary(ivars, interfaceId) : "manager-allocation");
        word(record, "boundary", boundary);
        evidence->setProperty("ItlwmNativePeerFailure", boundary);
        if (ok) {
            result = manager; // Family start consumes the allocation reference.
            word(record, "cleanup", "ownership-transferred-to-interface");
        } else if (manager) {
            // free() alone omits peers, callbacks and the data timer.
            // freeResources needs the lock; before it exists there are no peers.
            if (ivars && read<void *>(ivars, 0x78)) peerFreeResources(manager);
            auto *timer = SequoiaInterfaceLifecycle::take<OSObject>(
                const_cast<void *>(ivars), 0x710);
            OSSafeReleaseNULL(timer);
            manager->release();
            word(record, "cleanup", "released-after-failure");
        }
        // Publish only after all mutations: ioreg can serialize this collection
        // concurrently. Its retained dictionary must remain immutable.
        history->setObject(record);
        evidence->setProperty("ItlwmNativePeerAttempts", history);
        record->release();
    }
    history->release();
    evidence->setProperty("ItlwmNativePeerBuilt", result != nullptr);
    return result;
}

// r230: r229 proved the Skywalk BSD client attaches and is then discarded.
// Whether its start even wrote IOInterfaceName could not be attributed (the
// interface itself writes that property from several paths), so the client is
// sampled directly. The client object exists only while start is in flight, so
// a timer samples it: client+0xc0 turns non-zero when register_provider
// succeeds (it is passed back into the alloc call), +0xd0 and +0xf8 when that
// alloc completes, +0x144 when start returns success. The first non-zero field
// plus the sample in which the child disappears identifies the gate without
// another blind rebuild. r230's samples at 5 ms and later are all already
// absent - the whole start-and-discard runs inside those 5 ms - which is why
// r231 adds the synchronous burst below.
void itlwmPublishBsdClientProbeSample(IOService *target, void *interface, unsigned seq)
{
    if (!target || !interface) return;
    const uint64_t poolTx = read<uint64_t>(interface, 0x98);
    const uint64_t poolRx = read<uint64_t>(interface, 0xa0);
    const uint64_t link = read<uint64_t>(interface, 0xc0);
    const unsigned txType = poolTx
        ? read<uint8_t>(reinterpret_cast<void *>(static_cast<uintptr_t>(poolTx)), 0xb0) : 0;
    const unsigned rxType = poolRx
        ? read<uint8_t>(reinterpret_cast<void *>(static_cast<uintptr_t>(poolRx)), 0xb0) : 0;
    void *client = nullptr;
    auto *service = static_cast<IORegistryEntry *>(interface);
    OSIterator *children = service->getChildIterator(gIOServicePlane);
    if (children) {
        for (IORegistryEntry *child = nullptr;
             (child = static_cast<IORegistryEntry *>(children->getNextObject())) != nullptr; ) {
            const OSMetaClass *meta = child->getMetaClass();
            if (meta && strcmp(meta->getClassName(), "IOSkywalkNetworkBSDClient") == 0) {
                client = child;
                break;
            }
        }
        children->release();
    }
    char value[256];
    if (client) {
        snprintf(value, sizeof(value),
                 "e8=%llx f0=%llx b8=%llx c0=%llx d0=%llx f8=%llx st=%u k28=%u k130=%u "
                 "i98=%llx/%u iA0=%llx/%u iC0=%llx",
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xe8)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xf0)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xb8)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xc0)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xd0)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xf8)),
                 static_cast<unsigned>(read<uint8_t>(client, 0x144)),
                 static_cast<unsigned>(read<uint8_t>(client, 0x28)),
                 static_cast<unsigned>(read<uint32_t>(client, 0x130)),
                 static_cast<unsigned long long>(poolTx), txType,
                 static_cast<unsigned long long>(poolRx), rxType,
                 static_cast<unsigned long long>(link));
    } else {
        snprintf(value, sizeof(value), "absent i98=%llx/%u iA0=%llx/%u iC0=%llx",
                 static_cast<unsigned long long>(poolTx), txType,
                 static_cast<unsigned long long>(poolRx), rxType,
                 static_cast<unsigned long long>(link));
    }
    char key[40];
    snprintf(key, sizeof(key), "ItlwmNativeBsdProbe%02u", seq);
    target->setProperty(key, value);
}

// r231: the r230 timer lost the race. r229's synchronous census, microseconds
// after registerService returned, caught the client attached but pre-start;
// r230's first timer sample at 5 ms already found it gone. The whole
// start-and-discard runs inside that window, so only a synchronous burst on
// the publishing thread can observe it. The burst re-walks the child list
// every few microseconds, publishes each state change (16 slots, counted in
// the r231 ItlwmNativeBsdBurstIters/Hits/First/Slots properties), and reads
// the audited offsets directly:
//   +0x88 interface metaCast, +0xb0 and +0x90 the two following lookups,
//   +0xe8 NetworkInterface metaCast, +0xf0 RegistrationInfo,
//   +0xb8/+0xc0 registerNexusControllerProvider, +0xd0/+0xf8 nexus alloc,
//   +0x144 and +0x28 the success tail (IOService enabled byte).
// The interface's IOInterfaceName / "BSD Name" presence is sampled alongside,
// and the first child's class name separates Apple's KernelPipe fallback
// attach from the Network client.
static unsigned bsdBurstIters = 0;
static unsigned bsdBurstHits = 0;
static unsigned bsdBurstFirst = 0;
static unsigned bsdBurstSlots = 0;
static char bsdBurstLast[288] = {0};

void itlwmBsdBurstReset()
{
    bsdBurstIters = 0;
    bsdBurstHits = 0;
    bsdBurstFirst = 0;
    bsdBurstSlots = 0;
    bsdBurstLast[0] = '\0';
}

bool itlwmBsdBurstSample(IOService *target, void *interface, unsigned iteration)
{
    if (!target || !interface) return false;
    ++bsdBurstIters;
    auto *service = static_cast<IORegistryEntry *>(interface);
    void *client = nullptr;
    const char *childClass = nullptr;
    OSIterator *children = service->getChildIterator(gIOServicePlane);
    if (children) {
        unsigned seen = 0;
        for (IORegistryEntry *child = nullptr;
             (child = static_cast<IORegistryEntry *>(children->getNextObject())) != nullptr; ) {
            if (++seen > 8) break;
            const OSMetaClass *meta = child->getMetaClass();
            if (!meta) continue;
            if (!childClass) childClass = meta->getClassName();
            if (strcmp(meta->getClassName(), "IOSkywalkNetworkBSDClient") == 0) {
                client = child;
                break;
            }
        }
        children->release();
    }
    const bool nm = service->getProperty("IOInterfaceName") != nullptr;
    const bool bd = service->getProperty("BSD Name") != nullptr;
    char body[288];
    if (client) {
        ++bsdBurstHits;
        if (!bsdBurstFirst) bsdBurstFirst = iteration + 1;
        snprintf(body, sizeof(body),
                 "cls=%s e8=%llx f0=%llx i88=%llx iB0=%llx i90=%llx b8=%llx c0=%llx "
                 "d0=%llx f8=%llx k144=%u k28=%u k130=%u nm=%u bd=%u",
                 childClass ? childClass : "?",
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xe8)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xf0)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0x88)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xb0)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0x90)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xb8)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xc0)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xd0)),
                 static_cast<unsigned long long>(read<uint64_t>(client, 0xf8)),
                 static_cast<unsigned>(read<uint8_t>(client, 0x144)),
                 static_cast<unsigned>(read<uint8_t>(client, 0x28)),
                 static_cast<unsigned>(read<uint32_t>(client, 0x130)),
                 nm ? 1u : 0u, bd ? 1u : 0u);
    } else {
        snprintf(body, sizeof(body), "cls=%s absent nm=%u bd=%u",
                 childClass ? childClass : "-", nm ? 1u : 0u, bd ? 1u : 0u);
    }
    if (strcmp(body, bsdBurstLast) == 0) return false;
    strlcpy(bsdBurstLast, body, sizeof(bsdBurstLast));
    if (bsdBurstSlots < 16) {
        char value[304];
        snprintf(value, sizeof(value), "s=%u %s", iteration, body);
        char key[40];
        snprintf(key, sizeof(key), "ItlwmNativeBsdBurst%02u", bsdBurstSlots);
        target->setProperty(key, value);
        ++bsdBurstSlots;
    }
    return true;
}

void itlwmBsdBurstFinalize(IOService *target)
{
    if (!target) return;
    target->setProperty("ItlwmNativeBsdBurstIters",
                        static_cast<unsigned long long>(bsdBurstIters), 32);
    target->setProperty("ItlwmNativeBsdBurstHits",
                        static_cast<unsigned long long>(bsdBurstHits), 32);
    target->setProperty("ItlwmNativeBsdBurstFirst",
                        static_cast<unsigned long long>(bsdBurstFirst), 32);
    target->setProperty("ItlwmNativeBsdBurstSlots",
                        static_cast<unsigned long long>(bsdBurstSlots), 32);
    target->setProperty("ItlwmNativeBsdBurstDone", true);
}
#endif
