#ifndef AIRPORT_ITLWM_SEQUOIA_NATIVE_JOIN_H
#define AIRPORT_ITLWM_SEQUOIA_NATIVE_JOIN_H

#include <Airport/SequoiaJoinPolicy.h>
#include <Airport/SequoiaJoinEvents.h>
#include <Airport/SequoiaJoinCandidate.h>
#include <HAL/ItlEapolDiagnostic.h>

namespace SequoiaWCL {

// WCLNetManager::updateLinkState sends exactly 16 bytes. Padding 9..11 is
// uninitialized in the stock producer and is not a policy/control field.
struct LinkStateRequest {
    uint8_t bssid[6];
    uint8_t up;
    uint8_t publishInterface;
    uint8_t updateBss;
    uint8_t padding09[3];
    uint32_t debounceCode;
};
static_assert(sizeof(LinkStateRequest) == 16, "24G830 link update request");
static_assert(offsetof(LinkStateRequest, debounceCode) == 12, "24G830 down code");

struct LeaveRequest {
    uint32_t reason;
    uint32_t enhancedReason;
    uint16_t notificationReason;
    uint16_t waitMs;
    uint32_t notificationLinkReason;
    uint8_t deauthenticate;
    uint8_t notificationFlag;
    uint8_t notificationSecurity;
    uint8_t bssid[6];
    uint8_t padding19[3];
};
static_assert(sizeof(LeaveRequest) == 28, "24G830 leave request");
static_assert(offsetof(LeaveRequest, bssid) == 19, "24G830 leave peer");

// All fields are owned by the controller's shared workqueue. The external
// worker owns hardware until it has returned, even after a firmware reset.
struct NativeJoin {
    // Retained across later automatic reconnects.  The live attempt fields
    // below are intentionally reset for every request, while this snapshot
    // keeps the last failed request observable without retaining SSID,
    // BSSID, frame, nonce, MIC or key material.
    struct FailureSnapshot {
        uint32_t request = 0;
        uint32_t error = UINT32_MAX, startResult = UINT32_MAX;
        uint32_t authEvents = 0, assocEvents = 0;
        uint32_t authStatus = UINT32_MAX, assocStatus = UINT32_MAX;
        uint32_t stateError = UINT32_MAX, finalError = UINT32_MAX;
        uint32_t associationPosted = 0, completionPosted = 0;
        uint32_t completionStatus = UINT32_MAX, completionPostResult = UINT32_MAX;
        JoinCandidateDiagnostic candidate;
        ItlEapol::Snapshot handshake;
    } lastFailure;

    struct Diagnostics {
        uint32_t requests = 0;
        uint32_t lastRequestResult = UINT32_MAX;
        uint32_t policyResult = UINT32_MAX;
        uint32_t policyMask = 0, controls1e0 = 0, controls1e4 = 0, controls1e8 = 0;
        uint32_t controls210 = 0, controls3d0 = 0, batterySaveMode = 0;
        uint32_t extraKeyLength = 0, extraIELength = 0;
        uint32_t workerStarts = 0;
        uint32_t enableResult = UINT32_MAX;
        uint32_t startResult = UINT32_MAX;
        JoinCandidateDiagnostic candidate;
        ItlEapol::Snapshot handshake;
        uint32_t authEvents = 0, assocEvents = 0;
        uint32_t authStatus = UINT32_MAX, assocStatus = UINT32_MAX;
        uint32_t stateError = UINT32_MAX, finalError = UINT32_MAX;
        uint32_t associationPosted = 0, completionPosted = 0;
        uint32_t completionStatus = UINT32_MAX, completionPostResult = UINT32_MAX;
        uint32_t linkUpPosted = 0, linkDownPosted = 0, linkPostResult = UINT32_MAX;
        uint32_t linkCalls = 0, linkResult = UINT32_MAX, linkFlags = 0;
        uint32_t bssCalls = 0, bssResult = UINT32_MAX;
        uint32_t extBssCalls = 0, extBssResult = UINT32_MAX;
        uint32_t fastLaneCalls = 0, fastLaneResult = UINT32_MAX, fastLaneFlags = 0;
        uint32_t linkRequested = 0, connected = 0, drained = 0;
        uint32_t rejectStage = UINT32_MAX;
        // Last leave and retained failure contain only stages/results, never
        // peer identity. reset() intentionally preserves these diagnostics.
        uint32_t leaveRequests = 0, leaveResult = UINT32_MAX, leaveStage = 0;
        uint32_t leaveFailures = 0, leaveLastFailure = UINT32_MAX;
        uint32_t leaveLastFailureStage = 0, leaveLastFailureRequest = 0;
        uint32_t leaveWasBusy = 0, leaveDrained = 0, leaveBusyAfter = 0;
        uint32_t leaveScanCanceled = 0, leaveScanWaits = 0;
        uint32_t leaveTxError = 0;
    } diagnostics;
    JoinRequestSnapshot request;
    AssocEvent association = {};
    ConnectionCompleteEvent completion = {};
    uint64_t startedMs = 0;
    int generation = 0, error = 0;
    bool busy = false, worker = false, started = false, drained = false;
    bool cancel = false, abort = false, connected = false;
    bool linkRequested = false;
    bool linkUpPosted = false, linkDownPosted = false;
    LeaveRequest leave = {};
    bool leaveRequested = false, leaveWaiting = false, leaveAttempted = false;
    int leaveError = 0;
    bool associationReady = false, associationPosted = false, completionPosted = false;

    void rememberFailure()
    {
        auto &out = lastFailure;
        const auto &in = diagnostics;
        out.request = in.requests;
        out.error = static_cast<uint32_t>(error);
        out.startResult = in.startResult;
        out.authEvents = in.authEvents;
        out.assocEvents = in.assocEvents;
        out.authStatus = in.authStatus;
        out.assocStatus = in.assocStatus;
        out.stateError = in.stateError;
        out.finalError = in.finalError;
        out.associationPosted = in.associationPosted;
        out.completionPosted = in.completionPosted;
        out.completionStatus = in.completionStatus;
        out.completionPostResult = in.completionPostResult;
        out.candidate = in.candidate;
        out.handshake = in.handshake;
    }

    void reset()
    {
        request.clear();
        association = {};
        completion = {};
        startedMs = 0;
        generation = error = 0;
        busy = worker = started = drained = cancel = abort = connected = false;
        linkRequested = false;
        linkUpPosted = linkDownPosted = false;
        leave = {};
        leaveRequested = leaveWaiting = leaveAttempted = false;
        leaveError = 0;
        associationReady = associationPosted = completionPosted = false;
    }

    void observe(const ItlJoin::Progress &progress)
    {
        if (const auto *auth = progress.auth()) {
            diagnostics.authStatus = auth->status;
            if (!diagnostics.authEvents) diagnostics.authEvents = 1;
        }
        if (const auto *assoc = progress.assoc()) {
            diagnostics.assocStatus = assoc->status;
            if (!diagnostics.assocEvents) diagnostics.assocEvents = 1;
        }
        if (!associationReady && !cancel)
            associationReady = encodeObservedAssociation(progress, association);
    }

    void failureCompletion()
    {
        // Local timeout/transport failure is unspecified failure, not an AP
        // rejection. Preserve an observed nonzero IEEE result when available.
        completion.ieeeStatus = associationReady && association.ieeeStatus ? association.ieeeStatus : 1;
        completion.joinReason = 0xffff;
        completion.candidates[0].result = {0xe3ff8100u, 0xe3ff8100u};
        if (associationReady && association.ieeeStatus)
            completion.candidates[0].result = observedJoinDetail(association.ieeeStatus);
    }
};

constexpr uint32_t kJoinAbortCompleteMessage = 0xd6;

} // namespace SequoiaWCL
#endif
