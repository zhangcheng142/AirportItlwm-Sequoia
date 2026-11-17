//
//  AirportItlwmV2.hpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef AirportItlwmV2_hpp
#define AirportItlwmV2_hpp

#include "Apple80211.h"

#include "IOKit/network/IOGatedOutputQueue.h"
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>

#include "ItlIwm.hpp"
#include "ItlIwx.hpp"
#include "ItlIwn.hpp"

#include "AirportItlwmEthernetInterface.hpp"
#if __IO80211_TARGET >= __MAC_15_0
#include <Airport/SequoiaSkywalkRegistration.h>
#include <Airport/SequoiaNativeScan.h>
#include <Airport/SequoiaNativeJoin.h>
#include <Airport/SequoiaThreadCall.h>
#include <Airport/SequoiaPacketDiagnostics.h>
#include <Airport/SequoiaTrafficCounters.h>
#endif

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

#define kWatchDogTimerPeriod 1000

extern "C" {
const char *convertApple80211IOCTLToString(signed int cmd);
}

class AirportItlwm : public IO80211Controller {
    OSDeclareDefaultStructors(AirportItlwm)
#define IOCTL(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCGA80211) { \
ret = get##REQ(interface, (struct DATA_TYPE* )data); \
} else { \
ret = set##REQ(interface, (struct DATA_TYPE* )data); \
}
    
#define IOCTL_GET(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCGA80211) { \
ret = get##REQ(interface, (struct DATA_TYPE* )data); \
}
#define IOCTL_SET(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCSA80211) { \
ret = set##REQ(interface, (struct DATA_TYPE* )data); \
}
#define FUNC_IOCTL(REQ, DATA_TYPE) \
FUNC_IOCTL_GET(REQ, DATA_TYPE) \
FUNC_IOCTL_SET(REQ, DATA_TYPE)
#define FUNC_IOCTL_GET(REQ, DATA_TYPE) \
IOReturn get##REQ(OSObject *object, struct DATA_TYPE *data);
#define FUNC_IOCTL_SET(REQ, DATA_TYPE) \
IOReturn set##REQ(OSObject *object, struct DATA_TYPE *data);
    
public:
    virtual bool init(OSDictionary *properties) override;
    virtual void free() override;
    virtual IOService* probe(IOService* provider, SInt32* score) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
#if __IO80211_TARGET >= __MAC_15_0
    virtual IOReturn setProperties(OSObject *properties) override;
#endif
#if __IO80211_TARGET >= __MAC_15_0
    IOReturn enable(IO80211SkywalkInterface *netif);
    IOReturn disable(IO80211SkywalkInterface *netif);
#else
    virtual IOReturn enable(IO80211SkywalkInterface *netif) override;
    virtual IOReturn disable(IO80211SkywalkInterface *netif) override;
#endif
    virtual IOReturn setHardwareAddress(const void *addr, UInt32 addrBytes) override;
    virtual IOReturn getHardwareAddress(IOEthernetAddress* addrP) override;
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    virtual IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode) override;
    virtual IOReturn setMulticastMode(IOEnetMulticastMode mode) override;
    virtual IOReturn setMulticastList(IOEthernetAddress* addr, UInt32 len) override;
    virtual UInt32 getFeatures() const override;
    virtual const OSString * newVendorString() const override;
    virtual const OSString * newModelString() const override;
    virtual IOReturn selectMedium(const IONetworkMedium *medium) override;
    virtual bool createWorkQueue() override;
    virtual IONetworkInterface * createInterface() override;
    virtual bool configureInterface(IONetworkInterface *netif) override;
    virtual UInt32 outputPacket(mbuf_t, void * param) override;
#ifdef __PRIVATE_SPI__
    virtual IOReturn outputStart(IONetworkInterface *interface, IOOptionBits options) override;
    virtual IOReturn networkInterfaceNotification(
                        IONetworkInterface * interface,
                        uint32_t              type,
                        void *                  argument ) override;
#endif
    virtual bool setLinkStatus(
                               UInt32                  status,
                               const IONetworkMedium * activeMedium = 0,
                               UInt64                  speed        = 0,
                               OSData *                data         = 0) override;
    static IOReturn setLinkStateGated(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
    static IOReturn tsleepHandler(OSObject* owner, void* arg0 = 0, void* arg1 = 0, void* arg2 = 0, void* arg3 = 0);
    static void eventHandler(struct ieee80211com *, int, void *);
    IOReturn enableAdapter(IONetworkInterface *netif);
    IOReturn disableAdapter(IONetworkInterface *netif);
    bool initCCLogs();
    void releaseCCLogs();
    
#if __IO80211_TARGET >= __MAC_15_0
    virtual IO80211WorkQueue *getWorkQueue() const override;
    virtual void *getLogger() const override;
#else
    virtual IO80211WorkQueue *getWorkQueue() override;
#endif
    virtual bool requiresExplicitMBufRelease() override {
        return false;
    }
    virtual bool flowIdSupported() override {
        return false;
    }
    virtual SInt32 monitorModeSetEnabled(bool, UInt) override {
#if __IO80211_TARGET >= __MAC_15_0
        return kIOReturnUnsupported;
#else
        return kIOReturnSuccess;
#endif
    }
    virtual IOReturn requestQueueSizeAndTimeout(unsigned short *queue, unsigned short *timeout) override {
#if __IO80211_TARGET >= __MAC_15_0
        if (queue) *queue = 0;
        if (timeout) *timeout = 0;
        return kIOReturnUnsupported;
#else
        XYLog("%s\n", __FUNCTION__);
        return kIOReturnSuccess;
#endif
    }
    
    virtual bool getLogPipes(CCPipe**, CCPipe**, CCPipe**) override;
    
    virtual void *getFaultReporterFromDriver() override;
    // Defined in AirportItlwm.cpp: builds the virtual interface and the peer
    // manager the family's interface start cannot build with a real interface,
    // and reports both as void * so this translation unit never has to name
    // IO80211VirtualInterface.
    bool createNativePeerManager(ether_addr *eth, void **peerOut, void **virtualInterfaceOut);
    
#if __IO80211_TARGET < __MAC_15_0
    virtual SInt32 apple80211_ioctl(IO80211SkywalkInterface *,unsigned long,void *, bool, bool) override;
    virtual SInt32 apple80211SkywalkRequest(UInt,int,IO80211SkywalkInterface *,void *) override;
    virtual SInt32 apple80211SkywalkRequest(UInt,int,IO80211SkywalkInterface *,void *,void *) override;
#endif

    bool createMediumTables(const IONetworkMedium **primary);
    void releaseAll();
    void watchdogAction(IOTimerEventSource *timer);
    
    virtual SInt32 enableFeature(IO80211FeatureCode, void*) override;
    virtual bool isCommandProhibited(int command) override {
//        if (!ml_at_interrupt_context())
//            XYLog("%s %s\n", __FUNCTION__, convertApple80211IOCTLToString(command));
        return false;
    };
    virtual SInt32 handleCardSpecific(IO80211SkywalkInterface *,unsigned long,void *,bool) override;
    virtual IOReturn getDRIVER_VERSION(IO80211SkywalkInterface *interface,apple80211_version_data *data) override {
        XYLog("%s\n", __FUNCTION__);
        return getDRIVER_VERSION((OSObject *)interface, data);
    };
    virtual IOReturn getHARDWARE_VERSION(IO80211SkywalkInterface *interface,apple80211_version_data *data) override {
        XYLog("%s\n", __FUNCTION__);
        return getHARDWARE_VERSION((OSObject *)interface, data);
    };
    virtual IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface *interface,apple80211_capability_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return getCARD_CAPABILITIES((OSObject *)interface, data);
    }
    virtual IOReturn getPOWER(IO80211SkywalkInterface *interface,apple80211_power_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return getPOWER((OSObject *)interface, data);
    }
    virtual IOReturn setPOWER(IO80211SkywalkInterface *interface,apple80211_power_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return setPOWER((OSObject *)interface, data);
    }
    virtual IOReturn getCOUNTRY_CODE(IO80211SkywalkInterface *interface,apple80211_country_code_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return getCOUNTRY_CODE((OSObject *)interface, data);
    }
    virtual IOReturn setCOUNTRY_CODE(IO80211SkywalkInterface *interface,apple80211_country_code_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return setCOUNTRY_CODE((OSObject *)interface, data);
    }
    virtual IOReturn setGET_DEBUG_INFO(IO80211SkywalkInterface *interface,apple80211_debug_command *data) override {
#if __IO80211_TARGET >= __MAC_15_0
        return kIOReturnUnsupported;
#else
        XYLog("%s\n", __FUNCTION__);
        return kIOReturnSuccess;
#endif
    }
#if __IO80211_TARGET >= __MAC_15_0
    virtual IOReturn getPLATFORM_CONFIG(IO80211SkywalkInterface *, apple80211_platform_config *) override {
        return kIOReturnUnsupported;
    }
#endif
    
    //scan
    static void fakeScanDone(OSObject *owner, IOTimerEventSource *sender);
    
    //-----------------------------------------------------------------------
    // Power management support.
    //-----------------------------------------------------------------------
    virtual IOReturn registerWithPolicyMaker( IOService * policyMaker ) override;
    virtual IOReturn setPowerState( unsigned long powerStateOrdinal,
                                    IOService *   policyMaker) override;
    virtual IOReturn setWakeOnMagicPacket( bool active ) override;
    void setPowerStateOff(void);
    void setPowerStateOn(void);
    void unregistPM();
    bool initPCIPowerManagment(IOPCIDevice *provider);

    FUNC_IOCTL_GET(CARD_CAPABILITIES, apple80211_capability_data)
    FUNC_IOCTL(POWER, apple80211_power_data)
    FUNC_IOCTL_GET(DRIVER_VERSION, apple80211_version_data)
    FUNC_IOCTL_GET(HARDWARE_VERSION, apple80211_version_data)
    FUNC_IOCTL(COUNTRY_CODE, apple80211_country_code_data)
    
public:
    IOInterruptEventSource* fInterrupt;
    IOTimerEventSource *watchdogTimer;
    IOPCIDevice *pciNub;
    IONetworkStats *fpNetStats;
    AirportItlwmEthernetInterface *bsdInterface;
    IO80211SkywalkInterface *fNetIf;
    IOWorkLoop *fWatchdogWorkLoop;
    ItlHalService *fHalService;
#if __IO80211_TARGET >= __MAC_15_0
    bool startNative(IOService *provider);
    void stopNative(IOService *provider);
    void quiesceNativeSystemEvents();
    void releaseNativeSystemEvents();
    bool nativeAvailable();
    // Apple 24G830 requires IO80211Glue::sendIOUCToWcl (called by
    // prepareBSDInterface) to run while this work queue's gate is held, but
    // not on the work queue's own thread.  BSD attachment is initiated by
    // configd, so it must use this synchronous gate bridge.
    IOReturn prepareNativeBSDInterface(IO80211SkywalkInterface *, ifnet_t);
    bool nativeHardwareQueryAvailable();
    IOReturn getNativeVersion(apple80211_version_data *, bool);
    IOReturn getNativeCountry(apple80211_country_code_data *);
    SequoiaSkywalkRegistration nativeRegistration;
    bool nativeSuperStarted = false, nativeHalAttached = false;
    bool nativeServiceAttached = false, nativeControllerAttached = false;
    bool nativeInterfaceStarted = false, nativeGateAdded = false;
    bool nativeWatchdogAdded = false, nativeLoopRetained = false;
    // Apple publishes the Skywalk interface itself with IOOptionBits 8 after
    // infra registration, then clears its running state before returning from
    // start.  Keep both transitions observable so a missing CoreWLAN service
    // can be distinguished from a scan/cache problem.
    bool nativeInterfaceServicePublished = false;
    SInt32 nativeRunningStateResult = kIOReturnNotReady;
    bool nativeRunningStateApplied = false;
    UInt32 nativeTxOutputCalls = 0;
    UInt32 nativeTxOutputGated = 0;
    // Dedicated diagnostic loop; never the HAL/compatibility global loop.
    // stop drains the callback before controller/module teardown.
    IOWorkLoop *nativeBootWorkLoop = nullptr;
    IOTimerEventSource *nativeBootTimer = nullptr;
    unsigned nativeBootTicks = 0, nativeBootLastEvents = 0;
    bool nativeBootSettled = false;
    // r230: the Skywalk BSD client exists only while its start is in flight, so
    // a second bounded loop samples it (and the interface pool pair the same
    // start compares) from publication onward; the first non-zero client field
    // and the sample where the child disappears identify the failing gate.
    // See itlwmPublishBsdClientProbeSample.
    bool startNativeBsdProbe();
    void stopNativeBsdProbe();
    static void nativeBsdProbeAction(OSObject *, IOTimerEventSource *);
    IOWorkLoop *nativeBsdProbeWorkLoop = nullptr;
    IOTimerEventSource *nativeBsdProbeTimer = nullptr;
    uint32_t nativeBsdProbeSeq = 0;
    // WCL's driver-available transition is sent once while the interface is
    // prepared and once after both BSD/controller services are registered.
    // Keep the phase/count on the provider so a boot can prove the ordering
    // without relying on IOLog surviving a reset.
    void announceNativeDriverAvailable(uint32_t phase);
    // Read-only registration boundary snapshot.  This records the objects
    // Apple uses to hand an interface from Skywalk to IO80211/CoreWLAN; it
    // never invokes an unverified private registration entry point.
    void publishNativeRegistrationDiagnostics(const char *phase);
    // The controller's initial attach can invoke the BSD child before the
    // Skywalk registration records exist. Apple releases that attach from
    // the Skywalk boundary; keep an explicit, idempotent retry for the child
    // so a missed matching notification cannot leave only an enX shell.
    IOReturn tryNativeBSDChildAttach();
    UInt32 nativeBSDAttachAttempts = 0;
    SInt32 nativeBSDAttachLastResult = kIOReturnNotReady;
    // BSD ownership A/B (itlwm_bsd_owner=skywalk).  Apple reaches BSD through
    // IOSkywalkNetworkBSDClient::start, which builds and attaches the ifnet
    // itself and is the only path that runs the netif nexus callbacks that
    // initialize the packet queues.  When set, the driver skips its borrowed
    // legacy child and leaves BSD to the Skywalk registration; the default keeps
    // the legacy child so the comparison needs no second build.
    bool nativeSkywalkBSDOwner = false;
    uint32_t nativeDriverAvailableAnnouncements = 0;
    uint32_t nativeDriverAvailableLastPhase = UINT32_MAX;
    // Report stalled startup without deliberately panicking the host.
    unsigned nativeStallTicks = 0, nativeStallEvents = 0;
    const char *nativeStallStage = nullptr;
    static void nativeStageReport(OSObject *, IOTimerEventSource *);
    bool startNativeStageReporter();
    void stopNativeStageReporter();
    // Independent owned references. The family retains the adapter at start;
    // stop releases that reference before we detach/release the raw reporter.
    OSObject *nativeFaultAdapter = nullptr, *nativeRawFaultReporter = nullptr;
    bool nativeFaultReporterAttached = false;
    bool nativeReady = false, nativeStopping = false;
    // Reproduce the r162 WCL ordering as an explicit trial mode.  It is
    // selected only by itlwm_wcl_compat=r162 and leaves the newer cache/glue
    // experiments available for comparison in the same source build.
    bool nativeWclCompatR162 = false;
    bool nativeRadioTransition = false; // Serialized on the main workqueue.
    bool nativeFirmwareAnnounced = false; // First successful radio enable, under gate.
    uint32_t nativeMacRequests = 0, nativeMacChanges = 0;
    void drainNativeRadioTransition();
    bool nativeRadioAvailable();
    bool nativeTrafficAvailable();
    bool nativePortAvailable();
    UInt nativeTransmitPackets(IOSkywalkTxSubmissionQueue *, IOSkywalkPacket *const *, UInt);
    UInt32 nativeReceivePacket(mbuf_t);
    bool initNativePacket();
    void stopNativePacket();
    void retryNativeTransmit(UInt delay);
    static void nativePacketTimerAction(OSObject *, IOTimerEventSource *);
    IOTimerEventSource *nativePacketTimer = nullptr;
    bool nativePacketTimerAdded = false, nativeTxRetry = false;
    IOReturn nativePacketError = kIOReturnSuccess;
    SequoiaPacketIO::ReceiveDiagnostics nativeRxDiagnostics;
    SequoiaTrafficCounters nativeTrafficCounters;
    // HAL counters remain valid without a custom legacy interface.
    IONetworkStats nativeNetworkStats = {};
    IOLock *nativePMLock = nullptr;
    bool initNativeScan();
    IOReturn publishNativeLink(bool, UInt);
    IOReturn setNativeDataPath(bool);
    void stopNativeScan();
    IOReturn requestNativeScan(void *);
    IOReturn cancelNativeScan();
    IOReturn cancelAndWaitNativeScan();
    void runNativeScan();
    void publishNativeScanDiagnostics();
    // Records what the apple80211 dispatcher was asked for when it could not
    // answer: either the native path was not available yet, or the selector has no
    // implementation here. Published through publishNativeScanDiagnostics().
    void recordUnsupportedRequest(uint32_t selector, bool notReady);
    // r227: WCL capability-query acceptance (495/521/524 GETs, 575/585 SETs).
    // Implemented in native_scan_sequoia.inc; gate defaults on with
    // itlwm_wcl_queries=off restoring the old refusal.
    bool nativeWclQueriesEnabled();
    void recordWclQuery(uint32_t selector);
    // Counts a configuration setter the dispatcher now accepts, so the next boot
    // shows whether airportd's start-up sequence completes.
    void recordConfigurationSetter(uint32_t selector);
    static void nativeScanWorker(thread_call_param_t, thread_call_param_t);
    static void nativeScanPostWorker(thread_call_param_t, thread_call_param_t);
    static IOReturn nativeScanPostGated(OSObject *, void *, void *, void *, void *);
    static void nativeScanTimerAction(OSObject *, IOTimerEventSource *);
    SequoiaWCL::NativeScan nativeScan;
    SequoiaWCL::ScanDelivery::Slot *nativeScanStorage = nullptr;
    SequoiaThreadCall *nativeScanCall = nullptr;
    SequoiaThreadCall *nativeScanPostCall = nullptr;
    uint32_t nativeScanPostMask = 0;
    uint32_t nativeScanPostStatus = 0;
    IOTimerEventSource *nativeScanTimer = nullptr;
    bool nativeScanTimerAdded = false;
    // airportd sends a legacy scan ioctl after the native WCL request. These
    // counters are updated atomically because that ioctl may arrive off-gate.
    uint32_t nativeLegacyScanRequests = 0;
    uint32_t nativeLegacyScanAccepted = 0;
    uint32_t nativeLegacyScanLastCommand = UINT32_MAX;
    uint32_t nativeLegacyScanLastResult = UINT32_MAX;
    uint32_t nativeLegacySetScanRequests = 0;
    uint32_t nativeLegacySetScanMultipleRequests = 0;
    uint32_t nativeLegacySetScanLastResult = UINT32_MAX;
    void recordNativeLegacyScanSet(bool multiple, IOReturn result);
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
    void publishNativeJoinDiagnostics();
    void captureNativeJoinDiagnostics(bool reset = false);
    static void nativeJoinWorker(thread_call_param_t, thread_call_param_t);
    static void nativeJoinTimerAction(OSObject *, IOTimerEventSource *);
    SequoiaWCL::NativeJoin nativeJoin;
    SequoiaThreadCall *nativeJoinCall = nullptr;
    IOTimerEventSource *nativeJoinTimer = nullptr;
    bool nativeJoinTimerAdded = false;
#endif
    
    //IO80211
    uint8_t power_state;
    struct ieee80211_node *fNextNodeToSend;
    bool fScanResultWrapping;
    IOTimerEventSource *scanSource;
    
    u_int32_t current_authtype_lower;
    u_int32_t current_authtype_upper;
    UInt64 currentSpeed;
    UInt32 currentStatus;
    bool disassocIsVoluntary;
    char geo_location_cc[3];
    
    //pm
#if __IO80211_TARGET >= __MAC_15_0
    SequoiaThreadCall *powerOnThreadCall = nullptr;
    SequoiaThreadCall *powerOffThreadCall = nullptr;
#else
    thread_call_t powerOnThreadCall;
    thread_call_t powerOffThreadCall;
#endif
    UInt32 pmPowerState;
    IOService *pmPolicyMaker;
    UInt8 pmPCICapPtr;
    bool magicPacketEnabled;
    bool magicPacketSupported;
    
    //AWDL
    uint8_t *syncFrameTemplate;
    uint32_t syncFrameTemplateLength;
    uint8_t awdlBSSID[6];
    uint32_t awdlSyncState;
    uint32_t awdlElectionId;
    uint32_t awdlPresenceMode;
    uint16_t awdlMasterChannel;
    uint16_t awdlSecondaryMasterChannel;
    uint8_t *roamProfile;
    struct apple80211_btc_profiles_data *btcProfile;
    struct apple80211_btc_config_data btcConfig;
    uint32_t btcMode;
    uint32_t btcOptions;
    bool awdlSyncEnable;
    
    CCPipe *driverLogPipe;
#if __IO80211_TARGET >= __MAC_15_0
    CCLogStream *driverLogger;
#endif
    CCPipe *driverDataPathPipe;
    CCPipe *driverSnapshotsPipe;
    
    CCStream *driverFaultReporter;
};

#endif /* AirportItlwmV2_hpp */
