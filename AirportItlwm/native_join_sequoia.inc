bool AirportItlwm::initNativeJoin()
{
    nativeJoinCall = SequoiaThreadCall::allocate(nativeJoinWorker, this);
    if (!nativeJoinCall) return false;
    nativeJoinTimer = IOTimerEventSource::timerEventSource(this, nativeJoinTimerAction);
    if (!nativeJoinTimer || _fWorkloop->addEventSource(nativeJoinTimer) != kIOReturnSuccess) return false;
    nativeJoinTimerAdded = true;
    return true;
}

IOReturn AirportItlwm::requestNativeJoin(void *data)
{
    using namespace SequoiaWCL;
    // 0=radio, 1=busy, 2=HAL, 3=capture, 4=policy, 5=timer, 6=threadcall.
    enum : uint32_t { RejectRadio = 0, RejectBusy = 1, RejectHal = 2,
        RejectCapture = 3, RejectPolicy = 4, RejectTimer = 5, RejectThreadcall = 6 };
    if (nativeJoin.diagnostics.requests != UINT32_MAX) ++nativeJoin.diagnostics.requests;
    nativeJoin.diagnostics.rejectStage = UINT32_MAX;
    nativeJoin.diagnostics.candidate = {};
    auto finish = [this](IOReturn result) {
        nativeJoin.diagnostics.lastRequestResult = static_cast<uint32_t>(result);
        publishNativeJoinDiagnostics();
        return result;
    };
    if (!nativeRadioAvailable() || !power_state || !nativeJoinCall || !nativeJoinTimerAdded) {
        nativeJoin.diagnostics.rejectStage = RejectRadio;
        return finish(kIOReturnNotReady);
    }
    if (nativeJoin.busy) {
        nativeJoin.diagnostics.rejectStage = RejectBusy;
        return finish(kIOReturnBusy);
    }
    if (nativeScan.workerActive()) {
        const auto scan = cancelAndWaitNativeScan();
        if (scan != kIOReturnSuccess) {
            nativeJoin.diagnostics.rejectStage = RejectBusy;
            return finish(scan);
        }
    }
    if (nativeScan.delivery.busy()) {
        nativeJoin.diagnostics.rejectStage = RejectBusy;
        return finish(kIOReturnBusy);
    }
    if (!fHalService || !fHalService->getNativeHal()) {
        nativeJoin.diagnostics.rejectStage = RejectHal;
        return finish(kIOReturnUnsupported);
    }
    if (!nativeJoin.request.capture(data, sizeof(JoinRequest))) {
        nativeJoin.diagnostics.rejectStage = RejectCapture;
        return finish(kIOReturnBadArgument);
    }
    const auto &request = *nativeJoin.request.get();
    auto &diagnostics = nativeJoin.diagnostics;
    diagnostics.policyMask = unsupportedJoinControls(request);
    diagnostics.controls1e0 = request.controls1e0;
    diagnostics.controls1e4 = request.controls1e4;
    diagnostics.controls1e8 = request.controls1e8;
    diagnostics.controls210 = request.controls210;
    diagnostics.controls3d0 = request.controls3d0;
    diagnostics.batterySaveMode = request.batterySaveMode;
    diagnostics.extraKeyLength = request.extraKeyLength;
    diagnostics.extraIELength = request.extraIELength;
    const auto policy = validateJoinControls(nativeJoin.request);
    nativeJoin.diagnostics.policyResult = static_cast<uint32_t>(policy);
    if (policy != JoinPolicyResult::Success) {
        nativeJoin.diagnostics.rejectStage = RejectPolicy;
        nativeJoin.reset();
        return finish(policy == JoinPolicyResult::BadArgument ? kIOReturnBadArgument : kIOReturnUnsupported);
    }
    diagnostics.authEvents = diagnostics.assocEvents = 0;
    diagnostics.authStatus = diagnostics.assocStatus = UINT32_MAX;
    diagnostics.stateError = diagnostics.finalError = UINT32_MAX;
    diagnostics.associationPosted = diagnostics.completionPosted = 0;
    diagnostics.completionStatus = diagnostics.completionPostResult = UINT32_MAX;
    diagnostics.linkUpPosted = diagnostics.linkDownPosted = 0;
    diagnostics.linkPostResult = diagnostics.linkResult = diagnostics.bssResult = UINT32_MAX;
    diagnostics.linkCalls = diagnostics.linkFlags = diagnostics.bssCalls = 0;
    diagnostics.extBssCalls = diagnostics.fastLaneCalls = diagnostics.fastLaneFlags = 0;
    diagnostics.extBssResult = diagnostics.fastLaneResult = UINT32_MAX;
    diagnostics.linkRequested = diagnostics.connected = diagnostics.drained = 0;
    diagnostics.handshake = {};
    memcpy(nativeJoin.completion.candidates[0].bssid,
        nativeJoin.request.get()->candidates[0].bssid, 6);
    nativeJoin.completion.joinReason = 0xffff;
    nativeJoin.startedMs = airport_up_time();
    nativeJoin.busy = true;
    const auto armed = nativeJoinTimer->setTimeoutMS(10);
    if (armed != kIOReturnSuccess) {
        nativeJoin.diagnostics.rejectStage = RejectTimer;
        nativeJoin.reset();
        return finish(armed);
    }
    scheduleNativeJoin();
    if (!nativeJoin.worker) {
        nativeJoin.diagnostics.rejectStage = RejectThreadcall;
        return finish(kIOReturnNotReady);
    }
    return finish(kIOReturnSuccess);
}

void AirportItlwm::scheduleNativeJoin()
{
    if (!_fWorkloop->inGate() || !nativeJoinCall || !nativeJoin.busy || nativeJoin.worker) return;
    nativeJoin.worker = true;
    if (!nativeJoinCall->enter()) { nativeJoin.worker = false; nativeJoin.error = ECANCELED; }
}

IOReturn AirportItlwm::cancelNativeJoin(bool acknowledge)
{
    if (!_fWorkloop->inGate()) return kIOReturnCannotLock;
    if (!nativeJoinCall || !nativeJoinTimerAdded) return kIOReturnNotReady;
    if (!nativeJoin.busy) {
        if (!acknowledge) return kIOReturnSuccess;
        // WCL can race its abort with our failed completion. Still acknowledge
        // the abort through its own event after the (already idle) hardware.
        nativeJoin.busy = nativeJoin.drained = true;
    }
    nativeJoin.cancel = true;
    nativeJoin.abort |= acknowledge;
    nativeJoin.connected = false;
    if (!nativeJoin.drained) scheduleNativeJoin();
    _fCommandGate->commandWakeup(&nativeJoin, false);
    const auto armed = nativeJoinTimer->setTimeoutMS(1);
    if (armed != kIOReturnSuccess && !nativeJoin.error) nativeJoin.error = EIO;
    return armed;
}

void AirportItlwm::nativeJoinWorker(thread_call_param_t owner, thread_call_param_t)
{
    auto *self = static_cast<AirportItlwm *>(owner);
    self->getWorkQueue()->runAction([](OSObject *object, void *, void *, void *, void *) -> IOReturn {
        static_cast<AirportItlwm *>(object)->runNativeJoin();
        return kIOReturnSuccess;
    }, self);
}

IOReturn AirportItlwm::requestNativeLeave(void *data)
{
    if (!_fWorkloop->inGate()) return kIOReturnCannotLock;
    auto &d = nativeJoin.diagnostics;
    if (d.leaveRequests != UINT32_MAX) ++d.leaveRequests;
    d.leaveWasBusy = nativeJoin.busy ? 1 : 0;
    d.leaveDrained = d.leaveTxError = 0;
    // 1=context, 2=lifecycle, 3=payload, 4=policy, 5=busy, 6=peer,
    // 7=stop, 8=timer, 9=BSD publication, 10=WCL event drain, 11=TX, 12=done.
    auto finish = [&](IOReturn result, uint32_t stage) {
        d.leaveResult = static_cast<uint32_t>(result);
        d.leaveStage = stage;
        d.leaveBusyAfter = nativeJoin.busy ? 1 : 0;
        if (result != kIOReturnSuccess) {
            if (d.leaveFailures != UINT32_MAX) ++d.leaveFailures;
            d.leaveLastFailure = static_cast<uint32_t>(result);
            d.leaveLastFailureStage = stage;
            d.leaveLastFailureRequest = d.leaveRequests;
        }
        publishNativeJoinDiagnostics();
        return result;
    };
    if (_fWorkloop->onThread()) return finish(kIOReturnCannotLock, 1);
    if (!nativeAvailable() || !nativeJoinCall || !nativeJoinTimerAdded) return finish(kIOReturnNotReady, 2);
    if (!data) return finish(kIOReturnBadArgument, 3);
    SequoiaWCL::LeaveRequest request;
    memcpy(&request, data, sizeof(request));
    if (!request.reason || request.reason > UINT16_MAX || request.deauthenticate > 1 ||
        request.notificationFlag > 1 || request.notificationSecurity > 1) return finish(kIOReturnBadArgument, 3);
    if (request.enhancedReason || request.waitMs > 1000) return finish(kIOReturnUnsupported, 4);
    if (nativeRadioTransition || nativeJoin.leaveWaiting) return finish(kIOReturnBusy, 5);
    if (nativeScan.workerActive()) {
        d.leaveScanCanceled = 1;
        const auto scan = cancelAndWaitNativeScan();
        if (scan != kIOReturnSuccess) return finish(scan, 5);
        if (d.leaveScanWaits != UINT32_MAX) ++d.leaveScanWaits;
    }
    const uint8_t zero[6] = {};
    if (memcmp(request.bssid, zero, 6) && nativeJoin.busy &&
        memcmp(request.bssid, nativeJoin.completion.candidates[0].bssid, 6))
        return finish(kIOReturnBadArgument, 6);
    if (!nativeJoin.busy) {
        const auto published = publishNativeLink(false, 0);
        return finish(published, published == kIOReturnSuccess ? 12 : 9);
    }
    nativeJoin.leave = request;
    nativeJoin.leaveRequested = nativeJoin.leaveWaiting = true;
    // Normal leave is synchronous in WCLNetManager. Its caller changes state
    // immediately on return; do not acknowledge before the external stop joins.
    const auto canceled = cancelNativeJoin(false);
    while (nativeJoin.worker && nativeAvailable())
        _fCommandGate->commandSleep(&nativeJoin, THREAD_UNINT);
    nativeJoin.leaveWaiting = false;
    if (!nativeAvailable()) return finish(kIOReturnNotReady, 2);
    d.leaveDrained = nativeJoin.drained ? 1 : 0;
    if (!nativeJoin.drained) return finish(kIOReturnError, 7);
    const auto leaveError = nativeJoin.leaveError;
    d.leaveTxError = static_cast<uint32_t>(leaveError);
    const auto published = publishNativeLink(false, 0);
    if (published != kIOReturnSuccess) return finish(published, 9);
    // Finish the existing teardown path while still holding the workloop
    // gate: queue the old link-down (and any raced abort) before resetting
    // admission. WCL may submit the next MAC/candidate as soon as we return.
    // A failed event enqueue keeps busy set for the timer to retry; never
    // report a completed leave while stale state still blocks the next join.
    serviceNativeJoin();
    if (canceled != kIOReturnSuccess) return finish(canceled, 8);
    if (nativeJoin.busy) return finish(kIOReturnBusy, 10);
    // Teardown still completed after a missing TX response. Expose that
    // diagnostic instead of claiming successful over-air notification.
    return finish(leaveError ? kIOReturnError : kIOReturnSuccess, leaveError ? 11 : 12);
}

IOReturn AirportItlwm::finishNativeLinkConfiguration()
{
    if (!_fWorkloop || !_fWorkloop->inGate()) return kIOReturnCannotLock;
    if (!nativeRadioAvailable() || !nativeJoin.busy || !nativeJoin.started ||
        nativeJoin.cancel || nativeJoin.error || nativeJoin.drained ||
        !nativeJoin.completionPosted || !nativePortAvailable()) return kIOReturnNotReady;
    // 24G830 LINK_UP_DONE is a payload-free post-link power notification.
    // Native iwm_run already synchronously checked device/MAC power commands;
    // MAC power management remains disabled. No BCM radio-chain policy or
    // extra firmware wait is needed on this workloop callback.
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::requestNativeLink(void *data)
{
    if (!_fWorkloop->inGate()) return kIOReturnCannotLock;
    auto &d = nativeJoin.diagnostics;
    if (d.linkCalls != UINT32_MAX) ++d.linkCalls;
    auto finish = [&](IOReturn result) {
        d.linkResult = static_cast<uint32_t>(result);
        publishNativeJoinDiagnostics();
        return result;
    };
    if (!nativeAvailable()) return finish(kIOReturnNotReady);
    if (!data) return finish(kIOReturnBadArgument);
    SequoiaWCL::LinkStateRequest request;
    memcpy(&request, data, sizeof(request));
    d.linkFlags = request.up | (uint32_t(request.publishInterface) << 8) |
        (uint32_t(request.updateBss) << 16);
    if (request.up > 1 || request.publishInterface > 1 || request.updateBss > 1)
        return finish(kIOReturnBadArgument);
    // Deferred link-down/debounce is a separate WCL workflow; do not turn it
    // into an immediate disconnect while claiming to honor its control code.
    if (request.debounceCode) return finish(kIOReturnUnsupported);
    if (!request.up) {
        const uint8_t zero[6] = {};
        if (memcmp(request.bssid, zero, 6) && nativeJoin.busy &&
            memcmp(request.bssid, nativeJoin.completion.candidates[0].bssid, 6))
            return finish(kIOReturnBadArgument);
        const auto canceled = cancelNativeJoin(false);
        const auto published = publishNativeLink(false, 0);
        return finish(canceled != kIOReturnSuccess ? canceled : published);
    }
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    if (!nativeRadioAvailable() || !power_state || !hal || !nativeJoin.busy ||
        nativeJoin.cancel || nativeJoin.error || !nativeJoin.started || nativeJoin.drained ||
        !nativeJoin.associationPosted || nativeJoin.association.ieeeStatus ||
        nativeJoin.generation != hal->nativeGeneration() || hal->nativeStateErrorCode() ||
        !hal->nativeJoinProgressState().ownsPeer(request.bssid, nativeJoin.generation)) return finish(kIOReturnNotReady);
    // The owned BSS is already configured by HAL. WCL may first update BSS
    // metadata and only later request OS link publication. Never open data on
    // metadata-only updates or before our real key/connection completion.
    nativeJoin.linkRequested |= request.publishInterface != 0;
    nativeJoin.diagnostics.linkRequested = nativeJoin.linkRequested ? 1 : 0;
    serviceNativeJoin();
    const auto armed = nativeJoinTimer->setTimeoutMS(1);
    if (armed != kIOReturnSuccess) {
        nativeJoin.connected = false;
        nativeJoin.error = EIO;
        scheduleNativeJoin();
        _fCommandGate->commandWakeup(&nativeJoin, false);
    }
    return finish(armed);
}

void AirportItlwm::runNativeJoin()
{
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    if (nativeJoin.diagnostics.workerStarts != UINT32_MAX) ++nativeJoin.diagnostics.workerStarts;
    publishNativeJoinDiagnostics();
    auto wait = [&]() {
        AbsoluteTime deadline;
        clock_interval_to_deadline(10, kMillisecondScale, &deadline);
        _fCommandGate->commandSleep(&nativeJoin, deadline, THREAD_UNINT);
    };
    if (!nativeJoin.started && !nativeJoin.cancel && !nativeJoin.error && nativeRadioAvailable() && power_state && hal) {
        const auto enabled = hal->nativeEnable(bsdInterface);
        nativeJoin.diagnostics.enableResult = static_cast<uint32_t>(enabled);
        if (enabled != kIOReturnSuccess) nativeJoin.error = EIO;
        if (!nativeJoin.error && !nativeJoin.cancel && nativeRadioAvailable() && power_state) {
            nativeJoin.generation = static_cast<int>(hal->nativeGeneration());
            hal->nativeCandidateDiagnostic = {};
            captureNativeJoinDiagnostics(true);
            nativeJoin.error = hal->nativeJoinStart(nativeJoin.request, 0);
            nativeJoin.diagnostics.startResult = static_cast<uint32_t>(nativeJoin.error);
            nativeJoin.diagnostics.candidate = hal->nativeCandidateDiagnostic;
            nativeJoin.started = true;
        }
    }
    // The HAL copied security configuration before returning from join_start.
    // No timer, completion event or connected state retains the request key.
    nativeJoin.request.clear();
    uint64_t diagnosticMs = 0;
    while (!nativeJoin.error && !nativeJoin.cancel && nativeRadioAvailable() && power_state && hal) {
        nativeJoin.observe(hal->nativeJoinProgressState());
        nativeJoin.diagnostics.stateError = static_cast<uint32_t>(hal->nativeStateErrorCode());
        if (!nativeJoin.started || nativeJoin.generation != hal->nativeGeneration() ||
            hal->nativeStateErrorCode() || hal->nativeJoinProgressState().failed()) {
            nativeJoin.error = hal->nativeStateErrorCode() ? hal->nativeStateErrorCode() : ENETDOWN;
            break;
        }
        if (nativeJoin.connected) break;
        const auto now = airport_up_time();
        if (!diagnosticMs || now < diagnosticMs || now - diagnosticMs >= 1000) {
            captureNativeJoinDiagnostics();
            publishNativeJoinDiagnostics();
            diagnosticMs = now;
        }
        if (now < nativeJoin.startedMs || now - nativeJoin.startedMs >= 30000) {
            nativeJoin.error = ETIMEDOUT;
            break;
        }
        wait();
    }
    if (!nativeJoin.connected || !nativeRadioAvailable() || nativeJoin.cancel || nativeJoin.error) {
        nativeJoin.connected = false;
        // Retain the pre-disable supplicant/key/port state even after reset().
        captureNativeJoinDiagnostics();
        if (nativeJoin.leaveRequested && !nativeJoin.leaveAttempted && hal) {
            nativeJoin.leaveAttempted = true;
            do {
                nativeJoin.leaveError = hal->nativeLeave(nativeJoin.leave.deauthenticate != 0,
                    static_cast<uint16_t>(nativeJoin.leave.reason), nativeJoin.leave.waitMs);
                if (nativeJoin.leaveError == EBUSY) wait();
            } while (nativeJoin.leaveError == EBUSY && nativeAvailable());
        }
        if (!nativeJoin.error) nativeJoin.error = ECANCELED;
        if (hal) nativeJoin.observe(hal->nativeJoinProgressState());
        nativeJoin.failureCompletion();
        // disable can encounter a sleeping firmware state worker. Do not
        // declare drained or admit another request until it actually stops.
        IOReturn stopped = kIOReturnNotReady;
        if (hal) {
            do {
                stopped = hal->nativeDisable(bsdInterface);
                if (stopped == kIOReturnBusy) wait();
            } while (stopped == kIOReturnBusy);
        }
        nativeJoin.drained = stopped == kIOReturnSuccess;
        nativeJoin.diagnostics.drained = nativeJoin.drained ? 1 : 0;
        if (!nativeJoin.drained) nativeJoin.error = EIO;
        nativeJoin.diagnostics.finalError = static_cast<uint32_t>(nativeJoin.error);
        // Keep the failed attempt before reset/automatic reconnect can replace
        // the live diagnostics with a later successful join.
        nativeJoin.rememberFailure();
        setProperty("SequoiaNativeJoinError", static_cast<uint64_t>(nativeJoin.error), 32);
    }
    nativeJoin.diagnostics.connected = nativeJoin.connected ? 1 : 0;
    publishNativeJoinDiagnostics();
    nativeJoin.worker = false;
    _fCommandGate->commandWakeup(&nativeJoin, false);
    if (nativeAvailable() && nativeJoinTimerAdded) {
        const auto armed = nativeJoinTimer->setTimeoutMS(1);
        if (armed != kIOReturnSuccess) {
            nativeJoin.connected = false;
            nativeJoin.error = EIO;
        }
    }
}

void AirportItlwm::serviceNativeJoin()
{
    if (!nativeAvailable() || !nativeJoin.busy) return;
    auto *hal = fHalService ? fHalService->getNativeHal() : nullptr;
    if (!nativeJoin.cancel && nativeJoin.started && !nativeJoin.drained && hal) {
        const int watchdogError = hal->nativeWatchdog(airport_up_time());
        if (watchdogError && !nativeJoin.error) nativeJoin.error = watchdogError;
        nativeJoin.observe(hal->nativeJoinProgressState());
        nativeJoin.diagnostics.stateError = static_cast<uint32_t>(hal->nativeStateErrorCode());
        if (hal->nativeStateErrorCode() || hal->nativeJoinProgressState().failed() ||
            nativeJoin.generation != hal->nativeGeneration() || !nativeRadioAvailable() || !power_state)
            nativeJoin.error = hal->nativeStateErrorCode() ? hal->nativeStateErrorCode() : ENETDOWN;
    }
    auto post = [&](uint32_t kind, const void *bytes, size_t size) {
        // The final bool is isSendToWcl, not synchronous/asynchronous mode.
        // PostOffice::sendMail already copies/queues the payload. Passing
        // false bypasses the WCL join FSM in Skywalk::postMessageInternal.
        const auto result = postMessage(fNetIf, kind, const_cast<void *>(bytes), size, true);
        if (kind == SequoiaWCL::kConnectionCompleteMessage) {
            nativeJoin.diagnostics.completionPostResult = static_cast<uint32_t>(result);
            if (result == kIOReturnSuccess)
                nativeJoin.diagnostics.completionStatus = nativeJoin.completion.ieeeStatus;
        }
        if (kind == SequoiaWCL::kLinkStatusMessage)
            nativeJoin.diagnostics.linkPostResult = static_cast<uint32_t>(result);
        return result == kIOReturnSuccess;
    };
    if (nativeJoin.error || nativeJoin.cancel) {
        nativeJoin.connected = false;
        nativeJoin.diagnostics.connected = 0;
        nativeJoin.diagnostics.finalError = static_cast<uint32_t>(nativeJoin.error);
        if (!nativeJoin.drained) scheduleNativeJoin();
        if (publishNativeLink(false, 0) != kIOReturnSuccess) return;
        if (!nativeJoin.drained) return;
        if (nativeJoin.worker) return;
        if (nativeJoin.leaveWaiting) return;
        // Balance an accepted link indication only after hardware teardown.
        // Retry queue failure; do not discard the WCL link state on reset().
        if (nativeJoin.linkUpPosted && !nativeJoin.linkDownPosted) {
            SequoiaWCL::LinkStatusEvent link = {};
            memcpy(link.bssid, nativeJoin.completion.candidates[0].bssid, 6);
            link.reason = 0xff;
            if (!post(SequoiaWCL::kLinkStatusMessage, &link, sizeof(link))) return;
            nativeJoin.linkDownPosted = true;
            nativeJoin.diagnostics.linkDownPosted = 1;
        }
        if (nativeJoin.abort) {
            if (post(SequoiaWCL::kJoinAbortCompleteMessage, nullptr, 0)) nativeJoin.reset();
            return;
        }
        if (nativeJoin.leaveRequested) { nativeJoin.reset(); return; }
        if (nativeJoin.completionPosted) { nativeJoin.reset(); return; }
    }
    if (!nativeJoin.cancel && nativeJoin.associationReady && !nativeJoin.associationPosted) {
        if (!post(SequoiaWCL::kAssocEventMessage, &nativeJoin.association, sizeof(nativeJoin.association))) return;
        nativeJoin.associationPosted = true;
        nativeJoin.diagnostics.associationPosted = 1;
    }
    if (nativeJoin.drained && !nativeJoin.worker) {
        if (post(SequoiaWCL::kConnectionCompleteMessage, &nativeJoin.completion, sizeof(nativeJoin.completion))) {
            nativeJoin.diagnostics.completionPosted = 1;
            nativeJoin.reset();
        }
        return;
    }
    if (nativeJoin.error || nativeJoin.cancel || nativeJoin.connected || !nativeJoin.associationPosted ||
        nativeJoin.association.ieeeStatus || !nativePortAvailable()) return;
    // NET_MANAGER state0/event1 (join done) is ignored. Its separate d8/up
    // event0 invokes firstLinkUp while JOIN_MANAGER still owns the request.
    // Queue it before d5; reversing these lets firstLinkUp see "join out of
    // sync". Report only an authenticated, key-ready owned port, never a scan.
    if (!nativeJoin.linkUpPosted) {
        SequoiaWCL::LinkStatusEvent link = {};
        memcpy(link.bssid, nativeJoin.completion.candidates[0].bssid, 6);
        link.up = 1;
        link.reason = 0xff;
        if (!post(SequoiaWCL::kLinkStatusMessage, &link, sizeof(link))) return;
        nativeJoin.linkUpPosted = true;
        nativeJoin.diagnostics.linkUpPosted = 1;
    }
    if (!nativeJoin.completionPosted) {
        if (!post(SequoiaWCL::kConnectionCompleteMessage, &nativeJoin.completion, sizeof(nativeJoin.completion))) return;
        nativeJoin.completionPosted = true;
        nativeJoin.diagnostics.completionPosted = 1;
    }
    // d5 lets WCL finish its join state machine. Only its separate link update
    // authorizes interface publication; waiting for that request before d5 can
    // deadlock the stock WCL consumer. Data stays closed until both complete.
    if (!nativeJoin.linkRequested || publishNativeLink(true, 0) != kIOReturnSuccess) return;
    nativeJoin.connected = true;
    nativeJoin.diagnostics.connected = 1;
    captureNativeJoinDiagnostics();
    publishNativeJoinDiagnostics();
    _fCommandGate->commandWakeup(&nativeJoin, false);
}

void AirportItlwm::nativeJoinTimerAction(OSObject *owner, IOTimerEventSource *timer)
{
    auto *self = static_cast<AirportItlwm *>(owner);
    if (!self->getWorkQueue()->inGate() || timer != self->nativeJoinTimer || !self->nativeAvailable()) return;
    self->serviceNativeJoin();
    if (!self->nativeJoin.busy) return;
    const auto armed = timer->setTimeoutMS(self->nativeJoin.connected ? 100 : 10);
    if (armed != kIOReturnSuccess) {
        self->nativeJoin.connected = false;
        self->nativeJoin.error = EIO;
        self->scheduleNativeJoin();
        self->getCommandGate()->commandWakeup(&self->nativeJoin, false);
    }
}

void AirportItlwm::stopNativeJoin()
{
    if (nativeLoopRetained)
        _fWorkloop->runAction([](OSObject *owner, void *, void *, void *, void *) -> IOReturn {
            auto *self = static_cast<AirportItlwm *>(owner);
            if (self->nativeJoin.busy) self->cancelNativeJoin(false);
            if (self->nativeJoinTimerAdded) {
                self->nativeJoinTimer->cancelTimeout();
                self->nativeJoinTimer->disable();
            }
            return kIOReturnSuccess;
        }, this);
    if (nativeJoinCall) {
        if (nativeJoinCall->closeAndWait()) {
            // HAL detach below owns cleanup if we canceled a queued worker.
            _fWorkloop->runAction([](OSObject *owner, void *, void *, void *, void *) -> IOReturn {
                auto *self = static_cast<AirportItlwm *>(owner);
                self->nativeJoin.worker = false;
                self->getCommandGate()->commandWakeup(&self->nativeJoin, false);
                return kIOReturnSuccess;
            }, this);
        }
        SequoiaThreadCall::destroy(nativeJoinCall);
    }
    if (nativeJoinTimerAdded) {
        _fWorkloop->removeEventSource(nativeJoinTimer);
        nativeJoinTimerAdded = false;
    }
    OSSafeReleaseNULL(nativeJoinTimer);
    nativeJoin.request.clear();
}
