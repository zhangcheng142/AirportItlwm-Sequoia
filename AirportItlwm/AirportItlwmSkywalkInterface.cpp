//
//  AirportItlwmSkywalkInterface.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//
#include "AirportItlwmV2.hpp"
#include "AirportItlwmSkywalkInterface.hpp"
#include <sys/CTimeout.hpp>
#include <libkern/c++/OSMetaClass.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>
#if __IO80211_TARGET >= __MAC_15_0
#include <Airport/SequoiaWCL.h>
#include <Airport/SequoiaInterfaceLifecycle.h>
#include <mach/mach_time.h>
#endif

#define super IO80211InfraProtocol
OSDefineMetaClassAndStructors(AirportItlwmSkywalkInterface, IO80211InfraProtocol);

const char* hexdump(uint8_t *buf, size_t len) {
    ssize_t str_len = len * 3 + 1;
    char *str = (char*)IOMalloc(str_len);
    if (!str)
        return nullptr;
    for (size_t i = 0; i < len; i++)
    snprintf(str + 3 * i, (len - i) * 3, "%02x ", buf[i]);
    str[MAX(str_len - 2, 0)] = 0;
    return str;
}

static int ieeeChanFlag2appleScanFlagVentura(int flags)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    ret |= (APPLE80211_C_FLAG_ACTIVE | APPLE80211_C_FLAG_20MHZ);
    return ret;
}

static int ieeeChanFlag2apple(int flags, int bw)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    if (!(flags & IEEE80211_CHAN_PASSIVE))
        ret |= APPLE80211_C_FLAG_ACTIVE;
    if (flags & IEEE80211_CHAN_DFS)
        ret |= APPLE80211_C_FLAG_DFS;
    if (bw == -1) {
        if (flags & IEEE80211_CHAN_VHT) {
            if ((flags & IEEE80211_CHAN_VHT160) || (flags & IEEE80211_CHAN_VHT80_80))
                ret |= APPLE80211_C_FLAG_160MHZ;
            if (flags & IEEE80211_CHAN_VHT80)
                ret |= APPLE80211_C_FLAG_80MHZ;
        } else if ((flags & IEEE80211_CHAN_HT40) && (flags & IEEE80211_CHAN_HT)) {
            ret |= APPLE80211_C_FLAG_40MHZ;
            if (flags & IEEE80211_CHAN_HT40U)
                ret |= APPLE80211_C_FLAG_EXT_ABV;
        } else if (flags & IEEE80211_CHAN_HT20)
            ret |= APPLE80211_C_FLAG_20MHZ;
        else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
            ret |= APPLE80211_C_FLAG_10MHZ;
    } else {
        switch (bw) {
            case IEEE80211_CHAN_WIDTH_80P80:
            case IEEE80211_CHAN_WIDTH_160:
                ret |= APPLE80211_C_FLAG_160MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_80:
                ret |= APPLE80211_C_FLAG_80MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_40:
                ret |= APPLE80211_C_FLAG_40MHZ;
                if (flags & IEEE80211_CHAN_HT40U)
                    ret |= APPLE80211_C_FLAG_EXT_ABV;
                break;
            case IEEE80211_CHAN_WIDTH_20:
                ret |= APPLE80211_C_FLAG_20MHZ;
                break;
            default:
                if (flags & IEEE80211_CHAN_HT20)
                    ret |= APPLE80211_C_FLAG_20MHZ;
                else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
                    ret |= APPLE80211_C_FLAG_10MHZ;
                break;
        }
    }
    return ret;
}

void AirportItlwmSkywalkInterface::associateSSID(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    
    struct ieee80211_wpaparams     wpa;
    struct ieee80211_nwkey         nwkey;
    bzero(&wpa, sizeof(wpa));
    bzero(&nwkey, sizeof(nwkey));
    
    memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
    memcpy(ic->ic_des_essid, ssid, ssid_len);
    ic->ic_des_esslen = ssid_len;
    
    bool is_zero = true;
    for (int i = 0; i < IEEE80211_ADDR_LEN; i++)
    is_zero &= bssid.octet[i] == 0;
    
    if (!is_zero) {
        IEEE80211_ADDR_COPY(ic->ic_des_bssid, bssid.octet);
        ic->ic_flags |= IEEE80211_F_DESBSSID;
    }
    else {
        memset(ic->ic_des_bssid, 0, IEEE80211_ADDR_LEN);
        ic->ic_flags &= ~IEEE80211_F_DESBSSID;
    }

    // AUTHTYPE_WPA3_SAE AUTHTYPE_WPA3_FT_SAE
    // we don't really support WPA3, but we have announced we support WPA3 in card capability function. so we fake it as WPA2 to support some WPA2/WPA3 mix wifi connection.
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_SAE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_SAE) {
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2_PSK;// hack
    }
    // AUTHTYPE_WPA3_ENTERPRISE AUTHTYPE_WPA3_FT_ENTERPRISE
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_ENTERPRISE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_ENTERPRISE) {
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2;// hack
    }
    
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_protos = IEEE80211_WPA_PROTO_WPA1 | IEEE80211_WPA_PROTO_WPA2;
    }
    
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_PSK | IEEE80211_WPA_AKM_SHA256_PSK;
        wpa.i_enabled = 1;
        memcpy(ic->ic_psk, key, sizeof(ic->ic_psk));
        ic->ic_flags |= IEEE80211_F_PSK;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_8021X | IEEE80211_WPA_AKM_SHA256_8021X;
        wpa.i_enabled = 1;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    
    if (authtype_lower == APPLE80211_AUTHTYPE_SHARED) {
        XYLog("shared key authentication is not supported!\n");
        return;
    }
    
    if (authtype_upper == APPLE80211_AUTHTYPE_NONE && authtype_lower == APPLE80211_AUTHTYPE_OPEN) { // Open or WEP Open System
        if (key_len > 0) {
            XYLog("%s %d\n", __FUNCTION__, __LINE__);
            nwkey.i_wepon = IEEE80211_NWKEY_WEP;
            nwkey.i_defkid = key_index + 1;
            nwkey.i_key[key_index].i_keylen = (int)key_len;
            nwkey.i_key[key_index].i_keydat = key;
            ieee80211_ioctl_setnwkeys(ic, &nwkey);
        }
    }
}

void AirportItlwmSkywalkInterface::setPTK(const u_int8_t *key, size_t key_len) {
    if (!fHalService || !key || key_len == 0 || key_len > IEEE80211_KEYBUF_SIZE) return;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!ic || !ic->ic_bss || !ic->ic_set_key) return;
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;
    
    ni->ni_rsn_supp_state = RNSA_SUPP_PTKDONE;
    
    if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP) {
        u_int64_t prsc;
        
        /* check that key length matches that of pairwise cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
        if (key_len != keylen) {
            XYLog("PTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            return;
        }
        prsc = /*(gtk == NULL) ? LE_READ_6(key->rsc) :*/ 0;
        
        /* map PTK to 802.11 key */
        k = &ni->ni_pairwise_key;
        memset(k, 0, sizeof(*k));
        k->k_cipher = ni->ni_rsncipher;
        k->k_rsc[0] = prsc;
        k->k_len = keylen;
        memcpy(k->k_key, key, k->k_len);
        /* install the PTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            XYLog("setting PTK failed\n");
            return;
        }
        else
            XYLog("setting PTK successfully\n");
        ni->ni_flags &= ~IEEE80211_NODE_RSN_NEW_PTK;
        ni->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
        ni->ni_flags |= IEEE80211_NODE_RXPROT;
    } else if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP)
        XYLog("%s: unexpected pairwise key update received from %s\n",
              ic->ic_if.if_xname, ether_sprintf(ni->ni_macaddr));
}

void AirportItlwmSkywalkInterface::setGTK(const u_int8_t *gtk, size_t key_len, u_int8_t kid, u_int8_t *rsc) {
    if (!fHalService || !gtk || !rsc || key_len == 0 || key_len > IEEE80211_KEYBUF_SIZE ||
        kid >= IEEE80211_GROUP_NKID) return;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!ic || !ic->ic_bss || !ic->ic_set_key) return;
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;
    
    if (gtk != NULL) {
        /* check that key length matches that of group cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
        if (key_len != keylen) {
            XYLog("GTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            return;
        }
        /* map GTK to 802.11 key */
        k = &ic->ic_nw_keys[kid];
        if (k->k_cipher == IEEE80211_CIPHER_NONE || k->k_len != keylen || memcmp(k->k_key, gtk, keylen) != 0) {
            memset(k, 0, sizeof(*k));
            k->k_id = kid;    /* 0-3 */
            k->k_cipher = ni->ni_rsngroupcipher;
            k->k_flags = IEEE80211_KEY_GROUP;
            //if (gtk[6] & (1 << 2))
            //  k->k_flags |= IEEE80211_KEY_TX;
            k->k_rsc[0] = LE_READ_6(rsc);
            k->k_len = keylen;
            memcpy(k->k_key, gtk, k->k_len);
            /* install the GTK */
            if ((*ic->ic_set_key)(ic, ni, k) != 0) {
                XYLog("setting GTK failed\n");
                return;
            }
            else
                XYLog("setting GTK successfully\n");
        }
    }
    
    if (true) {
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
#ifndef IEEE80211_STA_ONLY
        if (ic->ic_opmode != IEEE80211_M_IBSS ||
            ++ni->ni_key_count == 2)
#endif
        {
            XYLog("marking port %s valid\n",
                  ether_sprintf(ni->ni_macaddr));
            ni->ni_port_valid = 1;
            ieee80211_set_link_state(ic, LINK_STATE_UP);
            ni->ni_assoc_fail = 0;
            if (ic->ic_opmode == IEEE80211_M_STA)
                ic->ic_rsngroupcipher = ni->ni_rsngroupcipher;
        }
    }
}

bool AirportItlwmSkywalkInterface::
init(IOService *provider
#if __IO80211_TARGET >= __MAC_15_0
     , ether_addr *selfAddress
#endif
     )
{
    bool ret = IO80211InfraInterface::init();
    if (!ret) {
        XYLog("%s IO80211InfraInterface init failed\n", __PRETTY_FUNCTION__);
        return false;
    }
    instance = OSDynamicCast(AirportItlwm, provider);
    if (!instance)
        return false;
#if __IO80211_TARGET >= __MAC_15_0
    if (!selfAddress)
        return false;
    const uint8_t zero[6] = {};
    if ((selfAddress->octet[0] & 1) || !memcmp(selfAddress->octet, zero, 6))
        return false;
    memcpy(nativePermanentAddress, selfAddress->octet, 6);
    setInitMacAddress(*selfAddress);
#endif
    this->fHalService = instance->fHalService;
    this->scanSource = instance->scanSource;
    return ret;
}

#if __IO80211_TARGET >= __MAC_15_0
#include <Airport/SequoiaPeerDiagnostics.h>
#include "native_interface_lifecycle_sequoia.inc"

void *AirportItlwmSkywalkInterface::createPeerManager()
{
    if (!instance) return nullptr;
    uint64_t peer = 0, controller = 0, stream = 0, pipe = 0;
    uint32_t role = 0;
    dumpNativeIvars(&peer, &controller, &role, &stream, &pipe);
    if (auto *provider = instance->getProvider()) {
        provider->setProperty("ItlwmNativePeer", peer, 64);
        provider->setProperty("ItlwmNativeCtrl", controller, 64);
        provider->setProperty("ItlwmNativeRole", role, 32);
        provider->setProperty("ItlwmNativeLogStream", stream, 64);
        provider->setProperty("ItlwmNativeLogPipe", pipe, 64);
    }
    return itlwmCreatePeerWithDiagnostics(this, instance, instance->getProvider(), instance->getWorkQueue());
}

void AirportItlwmSkywalkInterface::free()
{
    // 24G830 Skywalk::free dereferences +0x110 before testing it. Infra::init
    // allocates +0x118 only after Skywalk::init succeeds. With neither ivar
    // allocated, only the lower Skywalk Ethernet hierarchy needs unwinding.
    if (!skywalkIvars && !infraIvars) {
        IOSkywalkEthernetInterface::free();
        return;
    }
    super::free();
}

// r232: IOSkywalkNetworkBSDClient::start (IOSkywalkFamily 24G830 @0x2977c6b)
// fills the ifnet_init_eparams blob and calls this virtual (vptr slot 0x8e0)
// right before the alloc_net bind loop at 0x2977df0. r231's burst caught
// client+0xb8 and +0xc0 populated, then the client gone one sample later, so
// registerNexusControllerProvider succeeded and alloc_net returned a non-zero,
// non-EBUSY errno. Static analysis cleared every ifnet_allocate_extended gate
// and nx_create's provider-lookup / type / ENOTSUP gates; the three survivors
// all read values that only exist by the time this override runs:
//   ifnet_attach(ifp, *linkAddress)            -> the sockaddr_dl payload
//   nx_create pool metadata type/subtype       -> handle+0xc0/+0xc4 versus
//                                                 nxd+0x1c/+0x20
//   nx_create user-pool agreement              -> bit5 of *(handle+0x58)+0xe8
//                                                 versus npi_flags bit2, which
//                                                 start derives from the pool
//                                                 object's +0xb0 byte
// Read-only; the blob and the out pointer pass through untouched.
SInt32 AirportItlwmSkywalkInterface::initBSDInterfaceParameters(ifnet_init_eparams *params,
                                                               sockaddr_dl **linkAddress)
{
    using namespace SequoiaInterfaceLifecycle;
    IOService *target = instance ? instance->getProvider() : nullptr;
    const uint8_t *blob = reinterpret_cast<const uint8_t *>(params);
    const uint32_t flagsBefore = read<uint32_t>(blob, 0x08);
    const uint64_t client = read<uint64_t>(blob, 0x100);
    SInt32 result = super::initBSDInterfaceParameters(params, linkAddress);
    if (!target) return result;

    const void *clientPtr = reinterpret_cast<const void *>(client);
    const void *txPool = reinterpret_cast<const void *>(read<uint64_t>(this, 0x98));
    const void *rxPool = reinterpret_cast<const void *>(read<uint64_t>(this, 0xa0));
    const void *handle = reinterpret_cast<const void *>(read<uint64_t>(txPool, 0x18));
    const void *region = reinterpret_cast<const void *>(read<uint64_t>(handle, 0x58));
    const uint32_t regionFlags = read<uint32_t>(region, 0xe8);
    const void *link = linkAddress ? reinterpret_cast<const void *>(*linkAddress) : nullptr;
    const uint8_t nlen = read<uint8_t>(link, 5);
    uint64_t mac = 0;
    for (unsigned i = 0; i < 6 && nlen <= 12; ++i)
        mac |= static_cast<uint64_t>(read<uint8_t>(link, 8 + nlen + i)) << (8 * (5 - i));

    char value[384];
    snprintf(value, sizeof(value),
             "ret=%d ver=%u len=%u f08=%08x pre=%08x p20=%llx p28=%u p2c=%u p30=%u "
             "p48=%llx p58=%u p100=%llx p108=%llx p140=%u p144=%u p146=%u p148=%u",
             static_cast<int>(result),
             read<uint32_t>(blob, 0x00), read<uint32_t>(blob, 0x04),
             read<uint32_t>(blob, 0x08), flagsBefore,
             static_cast<unsigned long long>(read<uint64_t>(blob, 0x20)),
             read<uint32_t>(blob, 0x28), read<uint32_t>(blob, 0x2c),
             read<uint32_t>(blob, 0x30),
             static_cast<unsigned long long>(read<uint64_t>(blob, 0x48)),
             read<uint32_t>(blob, 0x58),
             static_cast<unsigned long long>(client),
             static_cast<unsigned long long>(read<uint64_t>(blob, 0x108)),
             read<uint32_t>(blob, 0x140),
             static_cast<unsigned>(read<uint16_t>(blob, 0x144)),
             static_cast<unsigned>(read<uint16_t>(blob, 0x146)),
             read<uint32_t>(blob, 0x148));
    target->setProperty("ItlwmNativeBsdParamBlob", value);

    snprintf(value, sizeof(value),
             "tx=%llx/%u rx=%llx/%u h=%llx f14=%08x c0=%u c4=%u r58=%llx re8=%08x bit5=%u "
             "ce0=%u c100=%llx c130=%u",
             static_cast<unsigned long long>(reinterpret_cast<uint64_t>(txPool)),
             static_cast<unsigned>(read<uint8_t>(txPool, 0xb0)),
             static_cast<unsigned long long>(reinterpret_cast<uint64_t>(rxPool)),
             static_cast<unsigned>(read<uint8_t>(rxPool, 0xb0)),
             static_cast<unsigned long long>(reinterpret_cast<uint64_t>(handle)),
             read<uint32_t>(handle, 0x14), read<uint32_t>(handle, 0xc0),
             read<uint32_t>(handle, 0xc4),
             static_cast<unsigned long long>(reinterpret_cast<uint64_t>(region)),
             regionFlags, (regionFlags >> 5) & 1u,
             read<uint32_t>(clientPtr, 0xe0),
             static_cast<unsigned long long>(read<uint64_t>(clientPtr, 0x100)),
             read<uint32_t>(clientPtr, 0x130));
    target->setProperty("ItlwmNativeBsdParamPool", value);

    snprintf(value, sizeof(value), "out=%llx len=%u fam=%u idx=%u type=%u nlen=%u alen=%u "
             "slen=%u mac=%012llx",
             static_cast<unsigned long long>(reinterpret_cast<uint64_t>(link)),
             static_cast<unsigned>(read<uint8_t>(link, 0)),
             static_cast<unsigned>(read<uint8_t>(link, 1)),
             static_cast<unsigned>(read<uint16_t>(link, 2)),
             static_cast<unsigned>(read<uint8_t>(link, 4)),
             static_cast<unsigned>(nlen), static_cast<unsigned>(read<uint8_t>(link, 6)),
             static_cast<unsigned>(read<uint8_t>(link, 7)),
             static_cast<unsigned long long>(mac));
    target->setProperty("ItlwmNativeBsdParamLink", value);
    return result;
}

IOReturn AirportItlwmSkywalkInterface::setMacAddress(ether_addr &address)
{
    if (!instance)
        return kIOReturnNotReady;
    // The controller checks the actual BSD owner under its workloop gate.
    // Skywalk owns the ifnet without creating our legacy bsdInterface child.
    return instance->setHardwareAddress(&address, sizeof(address));
}

IOReturn AirportItlwmSkywalkInterface::handleSequoiaRequest(UInt slot, void *data)
{
    // Native HAL RX, state workers and these queries share this workqueue.
    // Keep query node/IE access synchronous and never retain borrowed pointers.
    if (!instance || !instance->getWorkQueue())
        return kIOReturnNotReady;
    struct Request {
        UInt slot;
        void *data;
    } request = {slot, data};
    return instance->getWorkQueue()->runAction(
        [](OSObject *owner, void *arg0, void *, void *, void *) -> IOReturn {
            auto *interface = static_cast<AirportItlwmSkywalkInterface *>(owner);
            auto *request = static_cast<Request *>(arg0);
            return interface->dispatchSequoiaRequest(request->slot, request->data);
        }, this, &request);
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaLowLatencyInfo(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->nativeRadioAvailable()) return kIOReturnNotReady;
    // 24G830 WCLJoinManager unconditionally queries selector 0x1ab before
    // choosing candidates; Unsupported aborts the join before slot 593.
    // Apple's BCM implementation writes exactly two bytes and one uint16:
    // traffic ongoing, P2P realtime, preferred channel. With no low-latency
    // module it returns four zero bytes successfully. Our native path has no
    // such module either. This reports inactive state, not feature support.
    const uint32_t inactive = 0;
    memcpy(data, &inactive, sizeof(inactive));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaHardwareAddress(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->nativeHardwareQueryAvailable()) return kIOReturnNotReady;
    const uint8_t zero[6] = {};
    if ((nativePermanentAddress[0] & 1) || !memcmp(nativePermanentAddress, zero, 6))
        return kIOReturnNotReady;
    // WCLConfigManager::loadHwMacAddr asks for 12 bytes: version at 0,
    // permanent address at 4. It caches this for non-private joins. Return
    // the NVM identity captured at init, never the current randomized MAC.
    uint8_t output[12] = {};
    const uint32_t version = 1;
    memcpy(output, &version, sizeof(version));
    memcpy(output + 4, nativePermanentAddress, 6);
    memcpy(data, output, sizeof(output));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaMaxNssForAp(void *data)
{
    if (!data) return kIOReturnBadArgument;
    // 24G830 getMAX_NSS_FOR_AP: the controller handler gates the ioctl at 4
    // bytes, calls this slot with an 8-byte struct and copies the u32 at +4
    // into the request (0xffffff800221090f). BCM reads firmware iovar
    // "btc_nss" for the same field. This adapter is 1x1, so one stream is
    // the truthful maximum.
    uint8_t output[8] = {};
    const uint32_t maxNss = 1;
    memcpy(output + 4, &maxNss, sizeof(maxNss));
    memcpy(data, output, sizeof(output));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaVhtRate(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->nativeRadioAvailable() || !instance->nativePortAvailable())
        return kIOReturnNotReady;
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    ItlNativeHal::VhtRate rate = {};
    if (!hal || !hal->nativeVhtRate(rate)) return kIOReturnNotReady;
    // 24H23 ioctl195 requires 0x14 bytes; slot476 and BCM's ratespec decoder
    // agree on MCS/NSS/MHz/ns at +4/+8/+12/+16. Copy tolerates unaligned IOUCs.
    static_assert(sizeof(apple80211_mcs_vht_data) == 20, "Sequoia VHT rate query size");
    const apple80211_mcs_vht_data output = {
        APPLE80211_VERSION, rate.index, rate.nss, rate.bandwidthMHz, rate.guardIntervalNs};
    memcpy(data, &output, sizeof(output));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaRate(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->nativeRadioAvailable() || !instance->nativePortAvailable())
        return kIOReturnNotReady;
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    uint32_t mbps;
    if (!hal || !hal->nativeTxRateMbps(mbps)) return kIOReturnNotReady;
    static_assert(sizeof(apple80211_rate_data) == 24, "Sequoia RATE query size");
    apple80211_rate_data output = {};
    output.version = APPLE80211_VERSION;
    output.num_radios = 1;
    output.rate[0] = mbps;
    memcpy(data, &output, sizeof(output));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaMcs(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->nativeRadioAvailable() || !instance->nativePortAvailable())
        return kIOReturnNotReady;
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    uint32_t index;
    if (!hal || !hal->nativeMcsIndex(index)) return kIOReturnNotReady;
    const uint32_t output[2] = {APPLE80211_VERSION, index};
    memcpy(data, output, sizeof(output));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaNss(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->nativeRadioAvailable() || !instance->nativePortAvailable())
        return kIOReturnNotReady;
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    uint32_t nss = 0;
    if (!hal || !hal->nativeTxNss(nss)) return kIOReturnNotReady;
    // Slot504 gets 8 bytes, NSS at +4. The two 24H23 external handlers
    // return that u32 via 4-byte data or request.value (the live BSD route).
    const uint32_t output[2] = {APPLE80211_VERSION, nss};
    memcpy(data, output, sizeof(output));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaWclTrafficCounters(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->getWorkQueue() || !instance->getWorkQueue()->inGate() ||
        !instance->nativeAvailable()) return kIOReturnNotReady;
    // 24H23 selector434/slot521: six cumulative packet counts and sample ns.
    // Query while radio is off too, preserving the lifetime/time delta contract.
    uint64_t nowNs = 0;
    absolutetime_to_nanoseconds(mach_continuous_time(), &nowNs);
    uint64_t output[7] = {};
    instance->nativeTrafficCounters.snapshot(output, nowNs);
    memcpy(data, output, sizeof(output));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaWclChannelsInfo(void *data)
{
    if (!data) return kIOReturnBadArgument;
    // 24G830 getWCL_CHANNELS_INFO gates the ioctl at 0xc86 bytes: a 6-byte
    // header whose count sits at 0xc80, then 400 entries of 8 bytes. A zero
    // count is the same shape BCM returns when its channel table is empty.
    uint8_t output[0xc86] = {};
    memcpy(data, output, sizeof(output));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaWclHotChannels(void *data)
{
    if (!data) return kIOReturnBadArgument;
    // Broadcom's getWCL_FW_HOT_CHANNELS returns a count at +0x10 followed by
    // up to seven 16-bit channel specs. Intel has no matching firmware query;
    // an empty, well-shaped result tells WCL that there are no firmware-hot
    // channels without exposing stale caller memory as valid entries.
    const uint32_t count = 0;
    memcpy(static_cast<uint8_t *>(data) + 0x10, &count, sizeof(count));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaBeaconInfo(void *data)
{
    if (!data) return kIOReturnBadArgument;
    // WCLNetManager::setCurrentBSS issues selector 502 with a two-byte output
    // buffer, despite the lower-level BCM getBEACON_INFO API having a much
    // larger beacon-frame structure.  The two bytes are the QoS/Fastlane
    // capability pair copied from the current beacon.  Intel does not expose
    // Apple's Fastlane/ACM override, so report both capabilities disabled and
    // let WCL continue to the native association path.
    const uint8_t output[2] = {0, 0};
    memcpy(data, output, sizeof(output));
    return kIOReturnSuccess;
}

#include <Airport/SequoiaExtendedBss.h>

IOReturn AirportItlwmSkywalkInterface::dispatchSequoiaRequest(UInt slot, void *data)
{
    // Static identity is required while WCL initializes, before radio ready.
    if (slot == 505) return getSequoiaHardwareAddress(data);
    // Record before refusing: the family reaches this dispatcher with the
    // selector in %esi, and an unimplemented one is otherwise indistinguishable
    // from a scan that found nothing.
    if (!instance || !instance->nativeAvailable()) {
        if (instance) instance->recordUnsupportedRequest(slot, true);
        return kIOReturnNotReady;
    }
    if (slot == 592) return instance->requestNativeScan(data);
    if (slot == 587) return instance->cancelNativeScan();
    if (slot == 593) return instance->requestNativeJoin(data);
    if (slot == 590) return instance->cancelNativeJoin(true);
    if (slot == 598) return instance->requestNativeLink(data);
    if (slot == 595) return instance->finishNativeLinkConfiguration();
    if (slot == 519) return getSequoiaLowLatencyInfo(data);
    if (slot == 520) return getSequoiaBSSInfo(data);
    if (slot == 476) return getSequoiaVhtRate(data);
    if (slot == 468) return getSequoiaRate(data);
    if (slot == 473) return getSequoiaMcs(data);
    if (slot == 504) return getSequoiaNss(data);
    if (slot == 528) return getSequoiaExtendedBSSInfo(data);
    if (slot == 625) return setSequoiaFastLane(data);
    if (slot == 530) return getSequoiaBGScanCache(data);
    if (slot == 581) return instance->requestNativeLeave(data);
    if (slot == 583) return setSequoiaRoamLock(data);
    if (slot == 589) return setSequoiaArpMode(data);
    if (slot == 502) return getSequoiaBeaconInfo(data);
    // r227: WCL capability queries. The r226 boot's 117 unsupported requests
    // were these five slots: 495 getMAX_NSS_FOR_AP, 521 getWCL_TRAFFIC_COUNTERS,
    // 524 getWCL_CHANNELS_INFO, 575 setPM_MODE, 585 setWCL_ROAM_PROFILE_CONFIG.
    // Queries use audited fixed-size payloads. Traffic counts now come from
    // actual native packet handoffs; channel/coexistence placeholders remain.
    // itlwm_wcl_queries=off restores the old refusal for A/B.
    const bool wclQueries = instance->nativeWclQueriesEnabled();
    if (wclQueries) {
        if (slot == 518) {
            instance->recordWclQuery(518);
            return getSequoiaWclHotChannels(data);
        }
        if (slot == 495) {
            instance->recordWclQuery(495);
            return getSequoiaMaxNssForAp(data);
        }
        if (slot == 521) {
            instance->recordWclQuery(521);
            return getSequoiaWclTrafficCounters(data);
        }
        if (slot == 524) {
            instance->recordWclQuery(524);
            return getSequoiaWclChannelsInfo(data);
        }
    }
    // Configuration setters airportd issues while it brings the interface up.
    // They were the whole of the r157 unsupported-request record (320 refusals:
    // setPOWERSAVE 538, setIE 543, setBTCOEX_PROFILE 562,
    // setWCL_SET_SCAN_HOME_AWAY_TIME 596, setWCL_WNM_OPS 618,
    // setOS_FEATURE_FLAGS 604, setINFRA_ENUMERATED 630), and on that same boot
    // airportd's scans came back EBUSY while this driver's scan side was idle -
    // requests 234, accepted 234, terminals 234, requestActive 0, workerActive No,
    // pending 0, lastRequestResult 0. An EBUSY that cannot come from this driver
    // is what an incomplete configuration sequence looks like from the family's
    // side, so accept these and record it. None of them changes what this driver
    // puts on air: powersave stays off, no extra IEs are added, and the feature
    // flags and enumeration notice only tell the platform what it already asked.
    // setWCL_SET_SCAN_HOME_AWAY_TIME is the one with a real payload - the value
    // the family wants this interface to keep scans at - and is recorded so the
    // next boot shows whether airportd now gets past its configuration.
    // Enabling the audited BG-scan-cache capability makes 24G830 send its
    // WCL background-cache configuration sequence as well.  These payloads
    // are owned by airportd and their private field layouts are not needed by
    // the native foreground scan owner; accepting the requests as bounded
    // no-ops lets WCL finish capability setup without pretending to configure
    // an Intel firmware feature that has no native equivalent yet.
    // r227 adds 575 setPM_MODE and 585 setWCL_ROAM_PROFILE_CONFIG (the last
    // two of the r226 boot's 117 refused selectors); neither changes what
    // this driver puts on air, and both share the itlwm_wcl_queries gate.
    if (slot == 538 || slot == 543 || slot == 562 || slot == 563 || slot == 565 ||
        slot == 594 ||
        slot == 596 || slot == 604 || slot == 640 || slot == 652 ||
        slot == 608 ||
        slot == 609 || slot == 610 || slot == 611 || slot == 618 || slot == 630 ||
        (wclQueries && (slot == 575 || slot == 585))) {
        instance->recordConfigurationSetter(static_cast<uint32_t>(slot));
        return kIOReturnSuccess;
    }
    // Only fixed-size, audited query payloads can use the legacy helpers.
    // WCL scan/join/key requests must not be cast to the old ioctl structures.
    static_assert(sizeof(apple80211_channel_data) == 0x10, "Sequoia channel query size");
    static_assert(sizeof(apple80211_rssi_data) == 0x34, "Sequoia RSSI query size");
    static_assert(sizeof(apple80211_powersave_data) == 8, "Sequoia power query size");
    static_assert(sizeof(apple80211_opmode_data) == 8, "Sequoia mode query size");
    static_assert(sizeof(apple80211_mcs_data) == 8, "Sequoia MCS query size");
    static_assert(sizeof(apple80211_nss_data) == 8, "Sequoia NSS query size");
    static_assert(sizeof(apple80211_channels_info) == 0xa0c, "Sequoia channels-info query size");
    switch (slot) {
        case 465: // getCHANNEL
        case 466: // getPOWERSAVE
        case 469: // getOP_MODE
        case 470: // getRSSI
        case 471: // getSUPPORTED_CHANNELS (new layout)
        case 477: // getCHANNELS_INFO (legacy ioctl 207)
        case 490: // getHW_SUPPORTED_CHANNELS (new layout)
            break;
        default:
            instance->recordUnsupportedRequest(slot, false);
            return kIOReturnUnsupported;
    }
    if (!data)
        return kIOReturnBadArgument;
    if (!fHalService || !fHalService->get80211Controller() || !fHalService->getDriverInfo())
        return kIOReturnNotReady;
    switch (slot) {
        case 465: return getCHANNEL(static_cast<apple80211_channel_data *>(data));
        case 466: return getPOWERSAVE(static_cast<apple80211_powersave_data *>(data));
        case 469: return getOP_MODE(static_cast<apple80211_opmode_data *>(data));
        case 470: return getRSSI(static_cast<apple80211_rssi_data *>(data));
        case 471: return getSequoiaSupportedChannels(data, false);
        case 477: return getCHANNELS_INFO(static_cast<apple80211_channels_info *>(data));
        case 490: return getSequoiaSupportedChannels(data, true);
        default:
            instance->recordUnsupportedRequest(slot, false);
            return kIOReturnUnsupported;
    }
}

IOReturn AirportItlwmSkywalkInterface::getCHANNELS_INFO(apple80211_channels_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!fHalService || !fHalService->get80211Controller())
        return kIOReturnNotReady;

    // airportd still asks the native Skywalk interface for ioctl 207 before
    // starting a live scan.  Keep this a fixed-size, synchronous query and
    // derive every entry from the driver's actual NVM availability map.  The
    // old virtual implementation only filled channel numbers; Sequoia's
    // caller also consumes chanspec and restriction arrays, so leave no stale
    // bytes from a previous query while preserving unknown fields as zero.
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    auto *ic = fHalService->get80211Controller();
    uint16_t count = 0;
    for (unsigned i = 1; i <= IEEE80211_CHAN_MAX && count < APPLE80211_MAX_CHANNELS; ++i) {
        const auto &channel = ic->ic_channels[i];
        if (!channel.ic_freq || !isset(ic->ic_chan_avail, i))
            continue;
        const bool band2 = IEEE80211_IS_CHAN_2GHZ(&channel);
        const bool band5 = IEEE80211_IS_CHAN_5GHZ(&channel);
        if (band2 == band5)
            continue;
        const unsigned number = ieee80211_chan2ieee(ic, &channel);
        SequoiaWCL::LegacyChannelInfoEntry entry = {};
        if (!SequoiaWCL::legacyChannelInfo(
                number, band2 ? SequoiaWCL::Band::GHz2 : SequoiaWCL::Band::GHz5,
                (channel.ic_flags & IEEE80211_CHAN_PASSIVE) != 0,
                (channel.ic_flags & IEEE80211_CHAN_DFS) != 0,
                IEEE80211_IS_CHAN_HT40(&channel) || IEEE80211_IS_CHAN_VHT40(&channel),
                IEEE80211_IS_CHAN_VHT80(&channel), entry))
            continue;
        data->chan_spec[count] = entry.channelSpec;
        data->chan_num[count] = entry.channel;
        data->indoor_restric[count] = entry.indoorRestriction;
        data->radar_dfs[count] = entry.radarDFS;
        data->passive[count] = entry.passive;
        data->support_40Mhz[count] = entry.support40MHz;
        data->support_80Mhz[count] = entry.support80MHz;
        ++count;
    }
    data->num_chan_specs = count;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaSupportedChannels(void *data, bool hardware)
{
    using namespace SequoiaWCL;
    static_assert(Width20MHz == APPLE80211_C_FLAG_20MHZ && Band2GHz == APPLE80211_C_FLAG_2GHZ &&
                  Band5GHz == APPLE80211_C_FLAG_5GHZ && ActiveScan == APPLE80211_C_FLAG_ACTIVE &&
                  DFS == APPLE80211_C_FLAG_DFS, "Sequoia channel flags");
    if (!data)
        return kIOReturnBadArgument;
    if (!fHalService || !fHalService->get80211Controller())
        return kIOReturnNotReady;
    apple80211_country_code_data country = {};
    const uint8_t *currentCountry = nullptr;
    if (!hardware && static_cast<const uint8_t *>(data)[offsetof(SupportedChannels, countryOverride)]) {
        if (!instance) return kIOReturnNotReady;
        const IOReturn status = instance->getNativeCountry(&country);
        if (status != kIOReturnSuccess) return status;
        currentCountry = reinterpret_cast<const uint8_t *>(country.cc);
    }
    const auto *ic = fHalService->get80211Controller();
    Channel channels[IEEE80211_CHAN_MAX + 1];
    static_assert(ARRAY_SIZE(channels) <= kMaxSupportedChannels, "HAL channel inventory capacity");
    size_t count = 0;
    // ic_chan_active is PHY-mode dependent, not permission for active probing.
    // Both queries stay within the available NVM channel map. For now enumerate
    // primary 20 MHz channels only; bonded-channel geometry is not yet audited.
    for (unsigned i = 1; i <= IEEE80211_CHAN_MAX; ++i) {
        const auto &channel = ic->ic_channels[i];
        if (!channel.ic_freq || !isset(ic->ic_chan_avail, i))
            continue;
        bool band2 = IEEE80211_IS_CHAN_2GHZ(&channel);
        bool band5 = IEEE80211_IS_CHAN_5GHZ(&channel);
        if (band2 == band5)
            continue;
        if (channel20MHz(i, band2 ? Band::GHz2 : Band::GHz5,
                         channel.ic_flags & IEEE80211_CHAN_PASSIVE,
                         channel.ic_flags & IEEE80211_CHAN_DFS, channels[count]))
            ++count;
    }
    switch (encodeSupportedChannels(data, sizeof(SupportedChannels), channels, count, hardware, currentCountry)) {
        case ChannelQueryStatus::Success: return kIOReturnSuccess;
        case ChannelQueryStatus::BadArgument: return kIOReturnBadArgument;
        case ChannelQueryStatus::Unsupported: return kIOReturnUnsupported;
        case ChannelQueryStatus::NoSpace: return kIOReturnNoSpace;
    }
    return kIOReturnError;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaBSSInfo(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->getWorkQueue()->inGate() || !instance->nativeRadioAvailable())
        return kIOReturnNotReady;
    auto &d = instance->nativeJoin.diagnostics;
    if (d.bssCalls != UINT32_MAX) ++d.bssCalls;
    auto finish = [&](IOReturn result) {
        d.bssResult = static_cast<uint32_t>(result);
        instance->publishNativeJoinDiagnostics();
        return result;
    };
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    const auto &join = instance->nativeJoin;
    if (!hal || !join.busy || !join.started || join.cancel || join.error || join.drained ||
        !join.associationReady || join.association.ieeeStatus ||
        hal->nativeStateErrorCode() || join.generation != hal->nativeGeneration()) return finish(kIOReturnNotReady);
    const auto *node = hal->nativeController()->ic_bss;
    if (!node || !hal->nativeJoinProgressState().ownsPeer(node->ni_bssid, join.generation) ||
        !node->ni_rsnie_tlv || !node->ni_rsnie_tlv_len) return finish(kIOReturnNotReady);
    // WCL allocates 0x840 bytes and reads metadata + the encoded IE length.
    // Clear the unused tail, but never fabricate a current BSS on failure.
    memset(data, 0, SequoiaWCL::kMaxBeaconMessage);
    return finish(encodeWCLScanResult(node, data, SequoiaWCL::kMaxBeaconMessage)
        ? kIOReturnSuccess : kIOReturnNotReady);
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaExtendedBSSInfo(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->getWorkQueue()->inGate() || !instance->nativeRadioAvailable())
        return kIOReturnNotReady;
    auto &join = instance->nativeJoin;
    auto &d = join.diagnostics;
    if (d.extBssCalls != UINT32_MAX) ++d.extBssCalls;
    auto finish = [&](IOReturn result) {
        d.extBssResult = static_cast<uint32_t>(result);
        instance->publishNativeJoinDiagnostics();
        return result;
    };
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    if (!hal || !join.busy || !join.started || join.cancel || join.error || join.drained ||
        !join.associationReady || join.association.ieeeStatus || hal->nativeStateErrorCode() ||
        join.generation != hal->nativeGeneration()) return finish(kIOReturnNotReady);
    auto *ic = hal->nativeController();
    const auto *node = ic ? ic->ic_bss : nullptr;
    if (!node || ic->ic_state != IEEE80211_S_RUN ||
        !hal->nativeJoinProgressState().ownsPeer(node->ni_bssid, join.generation))
        return finish(kIOReturnNotReady);
    uint8_t ht[10] = {};
    if (node->ni_flags & IEEE80211_NODE_HT)
        for (unsigned i = 0; i < sizeof(ht); ++i) ht[i] = node->ni_rxmcs[i] & ic->ic_sup_mcs[i];
    uint16_t vht = 0xffff, he = 0xffff;
    if (node->ni_flags & IEEE80211_NODE_VHT)
        vht = SequoiaWCL::intersectMcsMaps(le16toh(node->ni_vht_mcsinfo.rx_mcs_map),
                                         le16toh(ic->ic_vht_tx_mcs_map));
    if (node->ni_flags & IEEE80211_NODE_HE) {
        const bool wide = node->ni_chw == IEEE80211_CHAN_WIDTH_160;
        const bool split = node->ni_chw == IEEE80211_CHAN_WIDTH_80P80;
        const auto &peer = node->ni_he_mcs_nss_supp;
        const auto &local = ic->ic_he_mcs_nss_supp;
        he = SequoiaWCL::intersectMcsMaps(
            le16toh(split ? peer.rx_mcs_80p80 : wide ? peer.rx_mcs_160 : peer.rx_mcs_80),
            le16toh(split ? local.tx_mcs_80p80 : wide ? local.tx_mcs_160 : local.tx_mcs_80));
    }
    return finish(SequoiaWCL::encodeExtendedBss(node->ni_rates.rs_rates, node->ni_rates.rs_nrates,
        ht, vht, he, node->ni_rsnie_tlv, node->ni_rsnie_tlv_len, data)
        ? kIOReturnSuccess : kIOReturnNotReady);
}

IOReturn AirportItlwmSkywalkInterface::setSequoiaFastLane(void *data)
{
    if (!data) return kIOReturnBadArgument;
    if (!instance || !instance->getWorkQueue()->inGate() || !instance->nativeRadioAvailable())
        return kIOReturnNotReady;
    // setCurrentBSS passes exactly two booleans. Native never enables Fastlane
    // or overrides WMM admission control. Honor disabled configuration; refuse
    // enable rather than claiming Broadcom's ACM override has been performed.
    uint8_t flags[2]; memcpy(flags, data, sizeof(flags));
    auto &d = instance->nativeJoin.diagnostics;
    if (d.fastLaneCalls != UINT32_MAX) ++d.fastLaneCalls;
    d.fastLaneFlags = flags[0] | (uint32_t(flags[1]) << 8);
    const auto result = flags[0] > 1 || flags[1] > 1 ? kIOReturnBadArgument :
        flags[0] ? kIOReturnUnsupported : kIOReturnSuccess;
    d.fastLaneResult = static_cast<uint32_t>(result);
    instance->publishNativeJoinDiagnostics();
    return result;
}

IOReturn AirportItlwmSkywalkInterface::setSequoiaRoamLock(void *data)
{
    if (!instance) return kIOReturnNotReady;
    if (!data) return kIOReturnBadArgument;
    // AppleBCMWLANCore::setWCL_SET_ROAM_LOCK reads only byte zero of the
    // audited payload. Do not accept arbitrary private data or claim that an
    // Intel firmware roam lock was programmed: the Intel native path has no
    // matching command. Returning success for the two valid boolean values is
    // the same compatibility contract as the other bounded WCL setters and
    // lets WCL continue its association preflight.
    const uint8_t value = *static_cast<const uint8_t *>(data);
    auto &d = instance->nativeScan.diagnostics;
    if (d.roamLockCalls != UINT32_MAX) ++d.roamLockCalls;
    d.roamLockLastValue = value;
    const IOReturn result = value <= 1 ? kIOReturnSuccess : kIOReturnBadArgument;
    d.roamLockLastResult = static_cast<uint32_t>(result);
    instance->publishNativeScanDiagnostics();
    return result;
}

IOReturn AirportItlwmSkywalkInterface::setSequoiaArpMode(void *data)
{
    if (!instance) return kIOReturnNotReady;
    if (!data) return kIOReturnBadArgument;
    // 24H23 AppleBCMWLANCore::setWCL_ARP_MODE reads a 0/1 mode at +8,
    // optional keepalive flags at +4/+5, and then programs Broadcom's ARP or
    // GARP offload. Intel firmware has no audited equivalent. Validate the
    // producer's mode/boolean fields and acknowledge the configuration while
    // leaving offload disabled; normal host ARP remains in the data path.
    const auto *bytes = static_cast<const uint8_t *>(data);
    uint32_t mode = 0;
    memcpy(&mode, bytes + 8, sizeof(mode));
    if (mode > 1) return kIOReturnUnsupported;
    if (bytes[4] > 1 || bytes[5] > 1) return kIOReturnBadArgument;
    instance->recordConfigurationSetter(589);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getSequoiaBGScanCache(void *data)
{
    auto &diagnostics = instance->nativeScan.diagnostics;
    if (diagnostics.cacheRequests != UINT32_MAX) ++diagnostics.cacheRequests;
    diagnostics.cacheLastResult = static_cast<uint32_t>(kIOReturnNotReady);
    diagnostics.cacheLastCount = 0;
    diagnostics.cacheLastValidEntries = 0;

    if (!data) {
        diagnostics.cacheLastResult = static_cast<uint32_t>(kIOReturnBadArgument);
        instance->publishNativeScanDiagnostics();
        return kIOReturnBadArgument;
    }
    if (!instance->getWorkQueue()->inGate() || !instance->nativeRadioAvailable() ||
        !fHalService || !fHalService->get80211Controller()) {
        if (diagnostics.cacheNotReady != UINT32_MAX) ++diagnostics.cacheNotReady;
        instance->publishNativeScanDiagnostics();
        return kIOReturnNotReady;
    }

    // The 24G830 caller supplies the fixed 0xb00-byte ABI buffer.  Zeroing it
    // first also guarantees that an empty/partially populated tree cannot
    // expose stale entries from a previous query.
    auto *list = static_cast<apple80211_bgscan_cached_network_data_list *>(data);
    memset(list, 0, sizeof(*list));
    auto *ic = fHalService->get80211Controller();
    uint32_t count = 0;
    for (auto *node = RB_MIN(ieee80211_tree, &ic->ic_tree);
         node && count < 140;
         node = RB_NEXT(ieee80211_tree, &ic->ic_tree, node)) {
        if (!node->ni_chan || node->ni_chan == IEEE80211_CHAN_ANYC ||
            !node->ni_esslen)
            continue;
        const unsigned channel = ieee80211_chan2ieee(ic, node->ni_chan);
        if (!channel || channel > UINT16_MAX)
            continue;
        auto &entry = list->entries[count];
        // Only fields whose width and location are established by Apple's
        // 24G830 adapter are populated.  The remaining private fields stay
        // zero until a public semantic definition exists.
        entry.value04 = static_cast<uint16_t>(channel);
        entry.value08 = node->ni_age_ts <= airport_up_time()
            ? static_cast<uint32_t>(airport_up_time() - node->ni_age_ts) : 0;
        entry.value0c = node->ni_esslen;
        entry.value10 = node->ni_rsnie_tlv ? node->ni_rsnie_tlv_len : 0;
        ++count;
    }
    list->count = count;
    list->timestamp = airport_up_time();
    diagnostics.cacheLastCount = count;
    diagnostics.cacheLastValidEntries = count;
    diagnostics.cacheLastResult = static_cast<uint32_t>(kIOReturnSuccess);
    if (diagnostics.cacheSuccesses != UINT32_MAX) ++diagnostics.cacheSuccesses;
    instance->publishNativeScanDiagnostics();
    return kIOReturnSuccess;
}

size_t AirportItlwmSkywalkInterface::encodeWCLScanResult(const struct ieee80211_node *node,
                                                       void *output, size_t capacity)
{
    // Native callers hold the HAL workqueue gate without sleeping while
    // reading the owned current node, its channel and complete beacon IEs.
    if (!node || !node->ni_chan || node->ni_chan == IEEE80211_CHAN_ANYC ||
        !fHalService || !fHalService->get80211Controller())
        return 0;
    bool band2 = IEEE80211_IS_CHAN_2GHZ(node->ni_chan);
    bool band5 = IEEE80211_IS_CHAN_5GHZ(node->ni_chan);
    if (band2 == band5)
        return 0;
    SequoiaWCL::BeaconInput input = {};
    input.ssid = node->ni_essid;
    input.ssidLength = node->ni_esslen;
    input.bssid = node->ni_bssid;
    input.ies = node->ni_rsnie_tlv;
    input.ieLength = node->ni_rsnie_tlv_len;
    input.channel = ieee80211_chan2ieee(fHalService->get80211Controller(), node->ni_chan);
    input.band = band2 ? SequoiaWCL::Band::GHz2 : SequoiaWCL::Band::GHz5;
    input.rssi = IWM_MIN_DBM + node->ni_rssi;
    input.capability = node->ni_capinfo;
    input.beaconInterval = node->ni_intval;
    return SequoiaWCL::encodeBeacon(input, output, capacity);
}
#endif

//ifnet_t AirportItlwmSkywalkInterface::
//getBSDInterface()
//{
//    if (instance->bsdInterface)
//        return instance->bsdInterface->getIfnet();
//    return NULL;
//}

IOReturn AirportItlwmSkywalkInterface::
getSSID(struct apple80211_ssid_data *sd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(sd, 0, sizeof(*sd));
        sd->version = APPLE80211_VERSION;
        memcpy(sd->ssid_bytes, ic->ic_des_essid, strlen((const char*)ic->ic_des_essid));
        sd->ssid_len = (uint32_t)strlen((const char*)ic->ic_des_essid);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->authtype_lower = current_authtype_lower;
    ad->authtype_upper = current_authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    current_authtype_lower = ad->authtype_lower;
    current_authtype_upper = ad->authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setCIPHER_KEY(struct apple80211_key *key)
{
    XYLog("%s\n", __FUNCTION__);
    if (!key) return kIOReturnBadArgument;
    static_assert(__offsetof(struct apple80211_key, key_ea) == 92, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, key_rsc_len) == 80, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_len) == 100, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kek_len) == 120, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_key) == 104, "struct corrupted");
    
    switch (key->key_cipher_type) {
        case APPLE80211_CIPHER_NONE:
            // clear existing key
//            XYLog("Setting NONE key is not supported\n");
            break;
        case APPLE80211_CIPHER_WEP_40:
        case APPLE80211_CIPHER_WEP_104:
            XYLog("Setting WEP key %d is not supported\n", key->key_index);
            break;
        case APPLE80211_CIPHER_TKIP:
        case APPLE80211_CIPHER_AES_OCB:
        case APPLE80211_CIPHER_AES_CCM:
            switch (key->key_flags) {
                case 4: // PTK
                    setPTK(key->key, key->key_len);
                    break;
                case 0: // GTK
                    setGTK(key->key, key->key_len, key->key_index, key->key_rsc);
                    break;
            }
            break;
        case APPLE80211_CIPHER_PMK:
            XYLog("Setting WPA PMK is not supported\n");
            break;
        case APPLE80211_CIPHER_MSK:
            XYLog("Setting MSK\n");
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
        case APPLE80211_CIPHER_PMKSA:
            XYLog("Setting WPA PMKSA\n");
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
    }
    //fInterface->postMessage(APPLE80211_M_CIPHER_KEY_CHANGED);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getPHY_MODE(struct apple80211_phymode_data *pd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    pd->version = APPLE80211_VERSION;
    pd->phy_mode = APPLE80211_MODE_11A
    | APPLE80211_MODE_11B
    | APPLE80211_MODE_11G
    | APPLE80211_MODE_11N;
    
    if (ic->ic_flags & IEEE80211_F_VHTON)
        pd->phy_mode |= APPLE80211_MODE_11AC;
    
    if (ic->ic_flags & IEEE80211_F_HEON)
        pd->phy_mode |= APPLE80211_MODE_11AX;
    
    switch (fHalService->get80211Controller()->ic_curmode) {
        case IEEE80211_MODE_AUTO:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
        case IEEE80211_MODE_11A:
            pd->active_phy_mode = APPLE80211_MODE_11A;
            break;
        case IEEE80211_MODE_11B:
            pd->active_phy_mode = APPLE80211_MODE_11B;
            break;
        case IEEE80211_MODE_11G:
            pd->active_phy_mode = APPLE80211_MODE_11G;
            break;
        case IEEE80211_MODE_11N:
            pd->active_phy_mode = APPLE80211_MODE_11N;
            break;
        case IEEE80211_MODE_11AC:
            pd->active_phy_mode = APPLE80211_MODE_11AC;
            break;
        case IEEE80211_MODE_11AX:
            pd->active_phy_mode = APPLE80211_MODE_11AX;
            break;
            
        default:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
    }
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCHANNEL(struct apple80211_channel_data *cd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss && ic->ic_bss->ni_chan &&
        ic->ic_bss->ni_chan != IEEE80211_CHAN_ANYC) {
        memset(cd, 0, sizeof(apple80211_channel_data));
        cd->version = APPLE80211_VERSION;
        cd->channel.version = APPLE80211_VERSION;
        cd->channel.channel = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
        cd->channel.flags = ieeeChanFlag2apple(ic->ic_bss->ni_chan->ic_flags, ic->ic_bss->ni_chw);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getSTATE(struct apple80211_state_data *sd)
{
    memset(sd, 0, sizeof(*sd));
    sd->version = APPLE80211_VERSION;
    sd->state = fHalService->get80211Controller()->ic_state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_INDEX_SET(struct apple80211_mcs_index_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        size_t size = min(ARRAY_SIZE(ic->ic_bss->ni_rxmcs), ARRAY_SIZE(ad->mcs_set_map));
        for (int i = 0; i < size; i++)
            ad->mcs_set_map[i] = ic->ic_bss->ni_rxmcs[i];
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getVHT_MCS_INDEX_SET(struct apple80211_vht_mcs_index_set_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode < IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_vht_mcs_index_set_data));
    data->version = APPLE80211_VERSION;
    data->mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_VHT(struct apple80211_mcs_vht_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode < IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_mcs_vht_data));
    data->version = APPLE80211_VERSION;
    data->guard_interval = (ieee80211_node_supports_vht_sgi80(ic->ic_bss) || ieee80211_node_supports_vht_sgi160(ic->ic_bss)) ? APPLE80211_GI_SHORT : APPLE80211_GI_LONG;
    data->index = ic->ic_bss->ni_txmcs;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    switch (ic->ic_bss->ni_chw) {
        case IEEE80211_CHAN_WIDTH_40:
            data->bw = 40;
            break;
        case IEEE80211_CHAN_WIDTH_80:
            data->bw = 80;
            break;
        case IEEE80211_CHAN_WIDTH_80P80:
        case IEEE80211_CHAN_WIDTH_160:
            data->bw = 160;
            break;
            
        default:
            data->bw = 20;
            break;
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE_SET(struct apple80211_rate_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        ad->num_rates = ic->ic_bss->ni_rates.rs_nrates;
        size_t size = min(ic->ic_bss->ni_rates.rs_nrates, ARRAY_SIZE(ad->rates));
        for (int i=0; i < size; i++) {
            struct apple80211_rate apple_rate = ad->rates[i];
            apple_rate.version = APPLE80211_VERSION;
            apple_rate.rate = ic->ic_bss->ni_rates.rs_rates[i];
            apple_rate.flags = 0;
        }
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getOP_MODE(struct apple80211_opmode_data *od)
{
#if __IO80211_TARGET >= __MAC_15_0
    if (!od) {
        nativeOPModeLastResult = kIOReturnBadArgument;
        if (nativeOPModeCalls != UINT32_MAX) ++nativeOPModeCalls;
        if (instance && instance->getProvider()) {
            instance->getProvider()->setProperty("ItlwmNativeOPModeCalls", nativeOPModeCalls, 32);
            instance->getProvider()->setProperty("ItlwmNativeOPModeLastResult",
                                                 static_cast<UInt64>(nativeOPModeLastResult), 32);
        }
        return nativeOPModeLastResult;
    }
    od->version = APPLE80211_VERSION;
    od->op_mode = APPLE80211_M_STA;
    nativeOPModeLastValue = od->op_mode;
    nativeOPModeLastResult = kIOReturnSuccess;
    if (nativeOPModeCalls != UINT32_MAX) ++nativeOPModeCalls;
    if (instance && instance->getProvider()) {
        instance->getProvider()->setProperty("ItlwmNativeOPModeCalls", nativeOPModeCalls, 32);
        instance->getProvider()->setProperty("ItlwmNativeOPModeLastResult",
                                             static_cast<UInt64>(nativeOPModeLastResult), 32);
        instance->getProvider()->setProperty("ItlwmNativeOPModeLastValue", nativeOPModeLastValue, 32);
    }
    return nativeOPModeLastResult;
#else
    if (!od) return kIOReturnBadArgument;
    od->version = APPLE80211_VERSION;
    od->op_mode = APPLE80211_M_STA;
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getTXPOWER(struct apple80211_txpower_data *txd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(txd, 0, sizeof(*txd));
        txd->version = APPLE80211_VERSION;
        txd->txpower = ic->ic_txpower;
        txd->txpower_unit = APPLE80211_UNIT_PERCENT;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE(struct apple80211_rate_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL)
        return 6;
    int nss;
    int sgi;
    int index = 0;
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->version = APPLE80211_VERSION;
        rd->num_radios = 1;
        sgi = ieee80211_node_supports_sgi(ic->ic_bss);
        if (ic->ic_curmode == IEEE80211_MODE_11AC) {
            if (sgi)
                index += 1;
            nss = fHalService->getDriverInfo()->getTxNSS();
            switch (ic->ic_bss->ni_chw) {
                case IEEE80211_CHAN_WIDTH_40:
                    index += 4;
                    break;
                case IEEE80211_CHAN_WIDTH_80:
                    index += 8;
                    break;
                case IEEE80211_CHAN_WIDTH_80P80:
                case IEEE80211_CHAN_WIDTH_160:
                    index += 12;
                    break;

                default:
                    break;
            }
            index += 2 * (nss - 1);
            const struct ieee80211_vht_rateset *rs = &ieee80211_std_ratesets_11ac[index];
            rd->rate[0] = rs->rates[ic->ic_bss->ni_txmcs % rs->nrates] / 2;
        } else if (ic->ic_curmode == IEEE80211_MODE_11N) {
            int is_40mhz = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_40;
            if (sgi)
                index += 1;
            if (is_40mhz)
                index += (IEEE80211_HT_RATESET_MIMO4_SGI + 1);
            index += (ic->ic_bss->ni_txmcs / 16);
            nss = ic->ic_bss->ni_txmcs / 8 + 1;
            index += 2 * (nss - 1);
            rd->rate[0] = ieee80211_std_ratesets_11n[index].rates[ic->ic_bss->ni_txmcs % 8] / 2;
        } else
            rd->rate[0] = ic->ic_bss->ni_rates.rs_rates[ic->ic_bss->ni_txrate];
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getBSSID(struct apple80211_bssid_data *bd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(bd, 0, sizeof(*bd));
        bd->version = APPLE80211_VERSION;
        memcpy(bd->bssid.octet, ic->ic_bss->ni_bssid, APPLE80211_ADDR_LEN);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSSI(struct apple80211_rssi_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss) {
        memset(rd, 0, sizeof(*rd));
        rd->version = APPLE80211_VERSION;
        rd->num_radios = 1;
        rd->rssi_unit = APPLE80211_UNIT_DBM;
        rd->rssi[0] = rd->aggregate_rssi
        = rd->rssi_ext[0]
        = rd->aggregate_rssi_ext
        = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef USE_APPLE_SUPPLICANT
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie == NULL) {
        return kIOReturnError;
    }
    data->version = APPLE80211_VERSION;
    if (ic->ic_rsn_ie_override[1] > 0) {
        data->len = 2 + ic->ic_rsn_ie_override[1];
        memcpy(data->ie, ic->ic_rsn_ie_override, data->len);
    }
    else {
        data->len = 2 + ic->ic_bss->ni_rsnie[1];
        memcpy(data->ie, ic->ic_bss->ni_rsnie, data->len);
    }
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef USE_APPLE_SUPPLICANT
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    static_assert(sizeof(ic->ic_rsn_ie_override) == APPLE80211_MAX_RSN_IE_LEN, "Max RSN IE length mismatch");
    memcpy(ic->ic_rsn_ie_override, data->ie, APPLE80211_MAX_RSN_IE_LEN);
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != nullptr)
        ieee80211_save_ie(data->ie, &ic->ic_bss->ni_rsnie);
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getAP_IE_LIST(struct apple80211_ap_ie_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie_tlv == NULL || ic->ic_bss->ni_rsnie_tlv_len == 0 || ic->ic_bss->ni_rsnie_tlv_len > data->len || ic->ic_bss->ni_rsnie_tlv_len > 1024)
        return kIOReturnError;
    data->version = APPLE80211_VERSION;
    data->len = ic->ic_bss->ni_rsnie_tlv_len;
    memcpy(data->ie_data, ic->ic_bss->ni_rsnie_tlv, data->len);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getNOISE(struct apple80211_noise_data *nd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(nd, 0, sizeof(*nd));
        nd->version = APPLE80211_VERSION;
        nd->num_radios = 1;
        nd->noise[0]
        = nd->aggregate_noise = -fHalService->getDriverInfo()->getBSSNoise();
        nd->noise_unit = APPLE80211_UNIT_DBM;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getPOWERSAVE(struct apple80211_powersave_data *pd)
{
    pd->version = APPLE80211_VERSION;
    pd->powersave_level = APPLE80211_POWERSAVE_MODE_DISABLED;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getNSS(struct apple80211_nss_data *data)
{
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setASSOCIATE(struct apple80211_assoc_data *ad)
{
    XYLog("%s [%s] mode=%d ad_auth_lower=%d ad_auth_upper=%d rsn_ie_len=%d%s%s%s%s%s%s%s\n", __FUNCTION__, ad->ad_ssid, ad->ad_mode, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_rsn_ie_len,
          (ad->ad_flags & 2) ? ", Instant Hotspot" : "",
          (ad->ad_flags & 4) ? ", Auto Instant Hotspot" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 1) ? ", don't disassociate" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 2) ? ", don't blacklist" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 4) ? ", closed Network" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 8) ? ", 802.1X" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 0x20) ? ", force BSSID" : "");
    
    struct apple80211_rsn_ie_data rsn_ie_data;
    struct apple80211_authtype_data auth_type_data;
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (!ad)
        return kIOReturnError;
    
    if (ic->ic_state < IEEE80211_S_SCAN)
        return kIOReturnSuccess;
    
    if (ic->ic_state == IEEE80211_S_ASSOC || ic->ic_state == IEEE80211_S_AUTH)
        return kIOReturnSuccess;

    if (ad->ad_mode != APPLE80211_AP_MODE_IBSS) {
        disassocIsVoluntary = false;
        auth_type_data.version = APPLE80211_VERSION;
        auth_type_data.authtype_upper = ad->ad_auth_upper;
        auth_type_data.authtype_lower = ad->ad_auth_lower;
        setAUTH_TYPE(&auth_type_data);
        rsn_ie_data.version = APPLE80211_VERSION;
        rsn_ie_data.len = ad->ad_rsn_ie[1] + 2;
        memcpy(rsn_ie_data.ie, ad->ad_rsn_ie, rsn_ie_data.len);
        setRSN_IE(&rsn_ie_data);

        associateSSID(ad->ad_ssid, ad->ad_ssid_len, ad->ad_bssid, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_key.key, ad->ad_key.key_len, ad->ad_key.key_index);
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDISASSOCIATE(struct apple80211_disassoc_data *ad)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (ic->ic_state < IEEE80211_S_SCAN)
        return kIOReturnSuccess;
    
    if (ic->ic_state > IEEE80211_S_AUTH && ic->ic_bss != NULL)
        IEEE80211_SEND_MGMT(ic, ic->ic_bss, IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_AUTH_LEAVE);
    
    if (ic->ic_state == IEEE80211_S_ASSOC || ic->ic_state == IEEE80211_S_AUTH)
        return kIOReturnSuccess;
    
    disassocIsVoluntary = true;

    ieee80211_del_ess(ic, nullptr, 0, 1);
    ieee80211_deselect_ess(ic);
#ifdef USE_APPLE_SUPPLICANT
    ic->ic_rsn_ie_override[1] = 0;
#endif
    ic->ic_assoc_status = APPLE80211_STATUS_UNAVAILABLE;
    ic->ic_deauth_reason = APPLE80211_REASON_ASSOC_LEAVING;
    ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSUPPORTED_CHANNELS(struct apple80211_sup_channel_data *ad)
{
    if (!ad)
        return kIOReturnError;
    memset(ad, 0, sizeof(*ad));
    ad->version = APPLE80211_VERSION;
    ad->num_channels = 0;
    struct ieee80211com *ic = fHalService->get80211Controller();
    for (int i = 0; i < IEEE80211_CHAN_MAX; i++) {
        if (ic->ic_channels[i].ic_freq != 0) {
            if (ad->num_channels >= ARRAY_SIZE(ad->supported_channels))
                return kIOReturnNoSpace;
            ad->supported_channels[ad->num_channels].version = APPLE80211_VERSION;
            ad->supported_channels[ad->num_channels].channel = ieee80211_chan2ieee(ic, &ic->ic_channels[i]);
            ad->supported_channels[ad->num_channels].flags = ieeeChanFlag2appleScanFlagVentura(ic->ic_channels[i].ic_flags);
            ad->num_channels++;
        }
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLOCALE(struct apple80211_locale_data *ld)
{
    if (!ld)
        return kIOReturnError;
    ld->version = APPLE80211_VERSION;
    ld->locale  = APPLE80211_LOCALE_FCC;
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getDEAUTH(struct apple80211_deauth_data *da)
{
    if (!da)
        return kIOReturnError;
    da->version = APPLE80211_VERSION;
    struct ieee80211com *ic = fHalService->get80211Controller();
    da->deauth_reason = ic->ic_deauth_reason;
//    XYLog("%s, %d\n", __FUNCTION__, da->deauth_reason);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getASSOCIATION_STATUS(struct apple80211_assoc_status_data *hv)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    if (!hv)
        return kIOReturnError;
    memset(hv, 0, sizeof(*hv));
    hv->version = APPLE80211_VERSION;
    if (ic->ic_state == IEEE80211_S_RUN)
        hv->status = APPLE80211_STATUS_SUCCESS;
    else
        hv->status = APPLE80211_STATUS_UNAVAILABLE;
//    XYLog("%s, %d\n", __FUNCTION__, hv->status);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCANCACHE_CLEAR(void *req)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();
    //if doing background or active scan, don't free nodes.
    if ((ic->ic_flags & IEEE80211_F_BGSCAN) || (ic->ic_flags & IEEE80211_F_ASCAN))
        return kIOReturnSuccess;
    ieee80211_free_allnodes(ic, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDEAUTH(struct apple80211_deauth_data *da)
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS(struct apple80211_mcs_data* md)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state != IEEE80211_S_RUN ||  ic->ic_bss == NULL || !md)
        return 6;
    md->version = APPLE80211_VERSION;
    md->index = ic->ic_bss->ni_txmcs;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLINK_CHANGED_EVENT_DATA(struct apple80211_link_changed_event_data *ed)
{
    if (ed == nullptr)
        return 16;
    
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    bzero(ed, sizeof(apple80211_link_changed_event_data));
    ed->isLinkDown = !(instance->currentStatus & kIONetworkLinkActive);
    if (ed->isLinkDown) {
        ed->voluntary = disassocIsVoluntary;
        ed->reason = APPLE80211_LINK_DOWN_REASON_DEAUTH;
    } else
        ed->rssi = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
    XYLog("Link %s, reason: %d, voluntary: %d\n", ed->isLinkDown ? "down" : "up", ed->reason, ed->voluntary);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCAN_REQ(struct apple80211_scan_data *sd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
#if 0
    XYLog("%s Type: %u BSS Type: %u PHY Mode: %u Dwell time: %u Rest time: %u Num channels: %u SSID: %s BSSID: %s\n",
          __FUNCTION__,
          sd->scan_type,
          sd->bss_type,
          sd->phy_mode,
          sd->dwell_time,
          sd->rest_time,
          sd->num_channels,
          sd->ssid,
          ether_sprintf(sd->bssid.octet));
#endif
    // Sequoia's WCL request (slot 592) owns the real native scan and its
    // 0xed completion.  airportd may still issue the legacy ioctl as a
    // synchronisation probe while net80211 remains in INIT; rejecting that
    // probe leaves CoreWLAN's outer scan marked Resource busy even though the
    // native WCL results are being delivered.  Accept the probe here without
    // starting the legacy cache path; the WCL request will provide the data.
#if __IO80211_TARGET >= __MAC_15_0
    if (instance && instance->nativeAvailable()) {
        instance->recordNativeLegacyScanSet(false, kIOReturnSuccess);
        return kIOReturnSuccess;
    }
#endif
    if (fScanResultWrapping)
        return 22;
    if (ic->ic_state <= IEEE80211_S_INIT)
        return 22;
    if (sd->scan_type == APPLE80211_SCAN_TYPE_FAST || sd->scan_type == APPLE80211_SCAN_TYPE_PASSIVE) {
        if (scanSource) {
            scanSource->setTimeoutMS(100);
            scanSource->enable();
        }
        return kIOReturnSuccess;
    }
    ieee80211_begin_cache_bgscan(&ic->ic_ac.ac_if);
    if (scanSource) {
        scanSource->setTimeoutMS(100);
        scanSource->enable();
    }
    return kIOReturnSuccess;
}

extern OSDictionary *convertScanToDictionary(apple80211_scan_result *a1);

static int convertNodeToScanResult(ItlHalService *fHalService, struct ieee80211_node *fNextNodeToSend, apple80211_scan_result *result)
{
    bzero(result, sizeof(*result));
    result->version = APPLE80211_VERSION;
    if (fNextNodeToSend->ni_rsnie_tlv && fNextNodeToSend->ni_rsnie_tlv_len > 0) {
        result->asr_ie_len = fNextNodeToSend->ni_rsnie_tlv_len;
        memcpy(result->asr_ie_data, fNextNodeToSend->ni_rsnie_tlv, MIN(result->asr_ie_len, sizeof(result->asr_ie_data)));
    } else {
        result->asr_ie_len = 0;
    }
    result->asr_beacon_int = fNextNodeToSend->ni_intval;
    for (int i = 0; i < result->asr_nrates; i++ )
        result->asr_rates[i] = fNextNodeToSend->ni_rates.rs_rates[i];
    result->asr_nrates = fNextNodeToSend->ni_rates.rs_nrates;
    result->asr_age = (uint32_t)(airport_up_time() - fNextNodeToSend->ni_age_ts);
    result->asr_cap = fNextNodeToSend->ni_capinfo;
    result->asr_channel.version = APPLE80211_VERSION;
    result->asr_channel.channel = ieee80211_chan2ieee(fHalService->get80211Controller(), fNextNodeToSend->ni_chan);
    result->asr_channel.flags = ieeeChanFlag2appleScanFlagVentura(fNextNodeToSend->ni_chan->ic_flags);
    result->asr_noise = -fHalService->getDriverInfo()->getBSSNoise();
    result->asr_rssi = -(0 - IWM_MIN_DBM - fNextNodeToSend->ni_rssi);
    memcpy(result->asr_bssid, fNextNodeToSend->ni_bssid, IEEE80211_ADDR_LEN);
    result->asr_ssid_len = fNextNodeToSend->ni_esslen;
    if (result->asr_ssid_len != 0)
        memcpy(&result->asr_ssid, fNextNodeToSend->ni_essid, result->asr_ssid_len);
    return 0;
}

IOReturn AirportItlwmSkywalkInterface::
getCURRENT_NETWORK(apple80211_scan_result *sr)
{
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || fHalService->get80211Controller()->ic_bss == NULL)
        return kIOReturnError;
    convertNodeToScanResult(fHalService, fHalService->get80211Controller()->ic_bss, sr);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCOLOCATED_NETWORK_SCOPE_ID(apple80211_colocated_network_scope_id *as)
{
    if (!as)
        return kIOReturnBadArgument;
    as->version = APPLE80211_VERSION;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSCAN_RESULT(struct apple80211_scan_result *sr)
{
    if (fNextNodeToSend == NULL) {
        if (fScanResultWrapping) {
            fScanResultWrapping = false;
            return 5;
        } else {
            fNextNodeToSend = RB_MIN(ieee80211_tree, &fHalService->get80211Controller()->ic_tree);
            if (fNextNodeToSend == NULL) {
                return 5;
            }
        }
    }
//    XYLog("%s ni_bssid=%s ni_essid=%s channel=%d flags=%d asr_cap=%d asr_nrates=%d asr_ssid_len=%d asr_ie_len=%d asr_rssi=%d\n", __FUNCTION__, ether_sprintf(fNextNodeToSend->ni_bssid), fNextNodeToSend->ni_essid, ieee80211_chan2ieee(ic, fNextNodeToSend->ni_chan), ieeeChanFlag2apple(fNextNodeToSend->ni_chan->ic_flags, -1), fNextNodeToSend->ni_capinfo, fNextNodeToSend->ni_rates.rs_nrates, fNextNodeToSend->ni_esslen, fNextNodeToSend->ni_rsnie_tlv == NULL ? 0 : fNextNodeToSend->ni_rsnie_tlv_len, fNextNodeToSend->ni_rssi);
    convertNodeToScanResult(fHalService, fNextNodeToSend, sr);
    
    fNextNodeToSend = RB_NEXT(ieee80211_tree, &HalService->get80211Controller()->ic_tree, fNextNodeToSend);
    if (fNextNodeToSend == NULL)
        fScanResultWrapping = true;

    return kIOReturnSuccess;
}
