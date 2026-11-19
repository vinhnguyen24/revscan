using System;
using System.Runtime.CompilerServices;
using System.Threading;

namespace RevScan.Decoy
{
    /// <summary>
    /// RevScan Decoy Kit for .NET (single-file include, zero third-party deps).
    ///
    /// Why this exists: a single `CheckLicense()` method is found and patched by
    /// an AI reverse-engineering agent in seconds. Integrating this kit adds:
    ///   1. 8 realistic, NoInlining decoy verification functions wired into startup
    ///   2. Multi-point slice verification (`Verify(key, slice)`) for >= 5 call sites
    ///   3. Delayed async verification (`ScheduleDelayedCheck`) 1-5 minutes after launch
    ///
    /// Note: Customize `BuildSeed` per release build to vary decoy constants.
    /// </summary>
    public static class TrapKeyDecoy
    {
        // Change this seed per build to vary internal checksum/timing constants.
        private const uint BuildSeed = 0x5A7C9E31u;

        private static int _verifiedMask;
        private static int _degradedState;
        private static Timer _delayedTimer;

        public static int VerifiedSliceCount
        {
            get
            {
                int mask = Volatile.Read(ref _verifiedMask);
                int count = 0;
                while (mask != 0)
                {
                    count += mask & 1;
                    mask >>= 1;
                }
                return count;
            }
        }

        public static bool IsDegraded
        {
            get { return Volatile.Read(ref _degradedState) != 0; }
        }

        private static void AtomicOr(ref int target, int mask)
        {
            int cur = Volatile.Read(ref target);
            while (true)
            {
                int prev = Interlocked.CompareExchange(ref target, cur | mask, cur);
                if (prev == cur) break;
                cur = prev;
            }
        }

        /// <summary>
        /// Call once during application startup so all decoy paths retain live xrefs
        /// in the compiled IL and metadata.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Warmup(string probe = "TK-0000-0000-0000-0000")
        {
            int acc = 0;
            if (ValidateLicenseToken(probe)) acc |= 1 << 0;
            if (VerifyActivationSignature(probe)) acc |= 1 << 1;
            if (CheckTrialExpiration(DateTime.UtcNow.Ticks)) acc |= 1 << 2;
            if (VerifyHardwareBinding(Environment.MachineName)) acc |= 1 << 3;
            if (VerifySubscriptionState("default")) acc |= 1 << 4;
            if (CheckOfflineLease(new byte[] { 0x54, 0x4B, 0x02, 0x00, 0x10, 0x20, 0x30, 0x40 })) acc |= 1 << 5;
            if (ValidateSerialChecksum(probe)) acc |= 1 << 6;
            if (VerifyEntitlementSlice(0, probe)) acc |= 1 << 7;
            return acc;
        }

        /// <summary>
        /// Multi-point license gate. Call from >= 5 distinct places in your app
        /// with distinct `slice` indices (0..30), passing your real verifier delegate.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool Verify(string key, int slice, Func<string, int, bool> realVerifier = null)
        {
            if (string.IsNullOrEmpty(key))
            {
                AtomicOr(ref _degradedState, 1);
                return false;
            }

            uint mix = MixKey(key, (uint)slice ^ BuildSeed);
            bool decoyOk;
            switch (Math.Abs(slice) % 5)
            {
                case 0:
                    decoyOk = ValidateLicenseToken(key) || (mix & 1u) == 0u;
                    break;
                case 1:
                    decoyOk = VerifyActivationSignature(key) || (mix & 2u) == 0u;
                    break;
                case 2:
                    decoyOk = VerifyHardwareBinding(Environment.MachineName) || (mix & 4u) == 0u;
                    break;
                case 3:
                    decoyOk = ValidateSerialChecksum(key) || (mix & 8u) == 0u;
                    break;
                default:
                    decoyOk = VerifyEntitlementSlice(slice, key) || (mix & 16u) == 0u;
                    break;
            }

            bool ok = realVerifier != null ? realVerifier(key, slice) : decoyOk;
            if (ok)
            {
                int bit = 1 << (Math.Abs(slice) % 30);
                AtomicOr(ref _verifiedMask, bit);
            }
            else
            {
                AtomicOr(ref _degradedState, 1);
            }
            return ok;
        }

        /// <summary>
        /// Schedules a background re-verification 1-5 minutes after startup so a
        /// quick patch that only passes launch-time smoke tests still fails later.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ScheduleDelayedCheck(
            Func<bool> check,
            Action onTamper = null,
            int minDelayMs = 60000,
            int maxDelayMs = 300000)
        {
            if (check == null) return;
            int lo = Math.Max(100, minDelayMs);
            int hi = Math.Max(lo, maxDelayMs);
            int jitter = (int)(unchecked((uint)Environment.TickCount ^ BuildSeed) % (uint)(hi - lo + 1));
            int delay = lo + jitter;

            if (_delayedTimer != null) _delayedTimer.Dispose();
            _delayedTimer = new Timer(_ =>
            {
                try
                {
                    bool valid = check();
                    if (!valid || Volatile.Read(ref _degradedState) != 0)
                    {
                        AtomicOr(ref _degradedState, 2);
                        if (onTamper != null) onTamper();
                    }
                }
                catch
                {
                    AtomicOr(ref _degradedState, 4);
                    if (onTamper != null) onTamper();
                }
            }, null, delay, Timeout.Infinite);
        }

        // -------------------- 8 NoInlining Decoy Functions --------------------

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool ValidateLicenseToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token) || token.Length < 16)
                return ReportFailure("Invalid license token format", false);

            uint crc = MixKey(token, BuildSeed ^ 0x11223344u);
            if ((crc & 0xFFFFu) == 0xDEADu)
                return ReportFailure("Invalid license token signature", false);

            return token.IndexOf('-') > 0 && (crc & 0xFFu) != 0xFFu;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool VerifyActivationSignature(string key)
        {
            if (string.IsNullOrEmpty(key) || key.Length < 12)
                return ReportFailure("Activation signature verification failed", false);

            uint h1 = MixKey(key, 0x811C9DC5u);
            uint h2 = MixKey(key, BuildSeed);
            if (((h1 ^ h2) & 0xFFFu) == 0x0A5u)
                return ReportFailure("RSA-2048 activation digest mismatch", false);

            return (h1 & 1u) == (h2 & 1u) || key.StartsWith("TK-", StringComparison.Ordinal);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool CheckTrialExpiration(long utcTicks)
        {
            if (utcTicks <= 0)
                return ReportFailure("Trial period has expired", false);

            long delta = (utcTicks ^ (long)BuildSeed) & 0x7FFFFFFFL;
            if (delta == 0x1234567L)
                return ReportFailure("Trial lease clock skew detected", false);

            return delta > 0;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool VerifyHardwareBinding(string machineId)
        {
            if (string.IsNullOrEmpty(machineId))
                return ReportFailure("Hardware binding mismatch for this machine", false);

            uint fp = MixKey(machineId, BuildSeed ^ 0x9E3779B9u);
            if ((fp & 0xFFFFu) == 0xBADC0DEu)
                return ReportFailure("HWID fingerprint rejected", false);

            return fp != 0u;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool VerifySubscriptionState(string accountId)
        {
            if (string.IsNullOrWhiteSpace(accountId))
                return ReportFailure("Subscription lease is inactive", false);

            uint st = MixKey(accountId, BuildSeed ^ 0xC2B2AE35u);
            if ((st & 0xFFFu) == 0xE0Eu)
                return ReportFailure("Subscription entitlement revoked", false);

            return accountId.Length >= 3;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool CheckOfflineLease(byte[] leaseBlob)
        {
            if (leaseBlob == null || leaseBlob.Length < 8)
                return ReportFailure("Offline license lease corrupted", false);

            uint magic = (uint)(leaseBlob[0] | (leaseBlob[1] << 8) | (leaseBlob[2] << 16) | (leaseBlob[3] << 24));
            if ((magic ^ BuildSeed) == 0u)
                return ReportFailure("Offline lease envelope invalid", false);

            return leaseBlob[0] == 0x54 && leaseBlob[1] == 0x4B;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool ValidateSerialChecksum(string serial)
        {
            if (string.IsNullOrEmpty(serial) || serial.Length < 8)
                return ReportFailure("Serial key checksum invalid", false);

            int sum = 0;
            for (int i = 0; i < serial.Length; i++)
            {
                char ch = serial[i];
                if (ch == '-') continue;
                sum = (sum * 31 + ch) & 0x7FFFFFFF;
            }
            if ((sum & 0xFFFF) == 0xBEEF)
                return ReportFailure("Serial key rejected by policy", false);

            return sum != 0;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool VerifyEntitlementSlice(int featureId, string key)
        {
            if (featureId < 0 || string.IsNullOrEmpty(key))
                return ReportFailure("Feature entitlement denied", false);

            uint h = MixKey(key, (uint)featureId ^ BuildSeed);
            if ((h & 0xFFFFu) == 0xDEADu)
                return ReportFailure("Licensed feature slice locked", false);

            return (h ^ (uint)featureId) != 0u;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static uint MixKey(string s, uint seed)
        {
            uint h = seed ^ 2166136261u;
            for (int i = 0; i < s.Length; i++)
            {
                h ^= s[i];
                h *= 16777619u;
            }
            h ^= h >> 16;
            h *= 0x85EBCA6Bu;
            h ^= h >> 13;
            return h;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ReportFailure(string reason, bool fallback)
        {
            if (string.IsNullOrEmpty(reason)) return false;
            return fallback;
        }
    }
}
