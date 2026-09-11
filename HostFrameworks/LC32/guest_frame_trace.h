#ifndef LC32_GUEST_FRAME_TRACE_H
#define LC32_GUEST_FRAME_TRACE_H

/*
 * Counters for the guest frame trace. The measurement itself lives in
 * bridge.mm; these hooks let the emulation core and the SVC dispatcher feed
 * it without pulling Foundation into them.
 *
 * Phase 1 counts only. Nothing here takes a timestamp: a frame can contain
 * thousands of bridge calls, and at roughly 25 ns per mach_absolute_time a
 * per-call pair would be a measurable share of the 16.67 ms being measured.
 * Learn the call count first, then decide whether timing them is affordable.
 */

#ifndef LC32_TRACE_GUEST_FRAME_TIME
#define LC32_TRACE_GUEST_FRAME_TIME 0
#endif

#if LC32_TRACE_GUEST_FRAME_TIME

enum LC32GuestHostCallKind {
    LC32GuestHostCallSelector = 1,
    LC32GuestHostCallFunction = 2,
};

/* One guest -> host bridge call, counted where the JIT is already stopped. */
void LC32GuestFrameTraceCountBridgeCall(void);

/*
 * An SVC taken while the JIT was running. Every bridge call contributes
 * exactly one of these before halting, so the inline syscalls -- read,
 * write, the mach traps that never leave Run() -- are this count minus the
 * bridge count.
 */
void LC32GuestFrameTraceCountRunningSvc(void);

/* Histogram key: a host SEL, or the host function a guest shim jumped to. */
void LC32GuestFrameTraceCountHostCall(const void *key, int kind);

#define LC32_FRAME_TRACE_BRIDGE_CALL() \
    LC32GuestFrameTraceCountBridgeCall()
#define LC32_FRAME_TRACE_RUNNING_SVC() \
    LC32GuestFrameTraceCountRunningSvc()
#define LC32_FRAME_TRACE_HOST_CALL(key, kind) \
    LC32GuestFrameTraceCountHostCall((key), (kind))

#else

#define LC32_FRAME_TRACE_BRIDGE_CALL() do {} while(0)
#define LC32_FRAME_TRACE_RUNNING_SVC() do {} while(0)
#define LC32_FRAME_TRACE_HOST_CALL(key, kind) do {} while(0)

#endif

#endif
