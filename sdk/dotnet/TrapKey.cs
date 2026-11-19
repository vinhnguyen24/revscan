using System;
using System.Runtime.InteropServices;

namespace RevScan
{
    /// <summary>
    /// Managed wrapper over RevScan.dll (see sdk/cpp/revscan.h).
    /// Keep <c>RevScan.dll</c> next to your exe, or embed it as a resource and
    /// extract on first run.
    /// </summary>
    public static class Native
    {
        private const string Dll = "RevScan.dll";

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int TK_Init(
            [MarshalAs(UnmanagedType.LPStr)] string productId,
            [MarshalAs(UnmanagedType.LPStr)] string modulusB64Url,
            [MarshalAs(UnmanagedType.LPStr)] string exponentHex,
            [MarshalAs(UnmanagedType.LPStr)] string serverUrl);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int TK_IsLicensed();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int TK_Activate([MarshalAs(UnmanagedType.LPStr)] string key);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int TK_Refresh();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int TK_Deactivate();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr TK_Hwid();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern long TK_DaysRemaining();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr TK_LastError();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void TK_Shutdown();
    }

    public enum Status
    {
        Ok = 0,
        NotInitialized = 1,
        InvalidArg = 2,
        NoLicense = 3,
        BadSignature = 4,
        Expired = 5,
        HwidMismatch = 6,
        Network = 7,
        Server = 8,
        SeatLimit = 9,
        KeyInvalid = 10,
        Internal = 11
    }

    public sealed class RevScanLicense
    {
        public string ProductId { get; }
        public string ModulusB64Url { get; }
        public string ExponentHex { get; }
        public string ServerUrl { get; }

        public RevScanLicense(string productId, string modulusB64Url, string exponentHex = "010001",
                              string serverUrl = null)
        {
            ProductId = productId ?? throw new ArgumentNullException(nameof(productId));
            ModulusB64Url = modulusB64Url ?? throw new ArgumentNullException(nameof(modulusB64Url));
            ExponentHex = exponentHex;
            ServerUrl = serverUrl;
        }

        public Status Init()
        {
            var st = (Status)Native.TK_Init(ProductId, ModulusB64Url, ExponentHex, ServerUrl);
            // TK_Init returns Ok even without a cached license; ask for the real state.
            return st == Status.Ok ? IsLicensed : st;
        }

        public Status IsLicensed => (Status)Native.TK_IsLicensed();

        public bool IsValid => IsLicensed == Status.Ok;

        public long DaysRemaining => Native.TK_DaysRemaining();

        public string Hwid => Marshal.PtrToStringAnsi(Native.TK_Hwid()) ?? string.Empty;

        public string LastError => Marshal.PtrToStringAnsi(Native.TK_LastError()) ?? string.Empty;

        public Status Activate(string key) => (Status)Native.TK_Activate(key);

        public Status Refresh() => (Status)Native.TK_Refresh();

        public Status Deactivate() => (Status)Native.TK_Deactivate();

        public void Shutdown() => Native.TK_Shutdown();
    }
}
