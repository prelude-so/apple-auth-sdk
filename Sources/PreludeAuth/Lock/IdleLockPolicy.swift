import Foundation

/// Decides whether time in the background has earned a seal.
/// Either clock crossing `threshold` seals, and so does the wall
/// clock running backwards.
struct IdleLockPolicy {
    let threshold: TimeInterval

    private let wallClock: () -> Date
    private let steadyClock: () -> TimeInterval
    private var backgroundedAt: (wall: Date, steady: TimeInterval)?

    init(
        threshold: TimeInterval,
        wallClock: @escaping () -> Date = Date.init,
        steadyClock: @escaping () -> TimeInterval = Self.continuousSeconds
    ) {
        self.threshold = threshold
        self.wallClock = wallClock
        self.steadyClock = steadyClock
    }

    /// Seconds since boot, including time spent asleep.
    static func continuousSeconds() -> TimeInterval {
        TimeInterval(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000_000
    }

    mutating func markBackgrounded() {
        backgroundedAt = (wallClock(), steadyClock())
    }

    /// Consumes the mark, so a foreground transition with no
    /// preceding background one never seals.
    mutating func shouldSealOnForeground() -> Bool {
        guard let backgroundedAt else {
            return false
        }
        self.backgroundedAt = nil

        let wall = wallClock().timeIntervalSince(backgroundedAt.wall)
        let steady = steadyClock() - backgroundedAt.steady
        return wall < 0 || wall >= threshold || steady >= threshold
    }
}
