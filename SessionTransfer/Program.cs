using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SessionTransfer
{
    class Interop
    {
        [DllImport("kernel32")]
        public static extern void GetWindowsDirectory(StringBuilder WinDir, int count);
        [DllImport("kernel32")]
        public static extern void GetSystemDirectory(StringBuilder SysDir, int count);

        public static IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
        public static void ShowMessageBox(string message, string title)
        {
            int resp = 0;
            WTSSendMessage(
                WTS_CURRENT_SERVER_HANDLE,
                WTSGetActiveConsoleSessionId(),
                title, title.Length,
                message, message.Length,
                0, 0, out resp, false);
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int WTSGetActiveConsoleSessionId();
        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSSendMessage(
            IntPtr hServer,
            int SessionId,
            String pTitle,
            int TitleLength,
            String pMessage,
            int MessageLength,
            int Style,
            int Timeout,
            out int pResponse,
            bool bWait);
        public static void CreateProcess(string app, string path, string cmdline)
        {
            bool result;
            IntPtr hToken = WindowsIdentity.GetCurrent().Token;
            IntPtr hDupedToken = IntPtr.Zero;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.Length = Marshal.SizeOf(sa);
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            int dwSessionID = WTSGetActiveConsoleSessionId();
            result = WTSQueryUserToken(dwSessionID, out hToken);

            if (!result)
            {
                Console.WriteLine("E: WTSQueryUserToken failed");
            }
            else
            {
                Console.WriteLine("C: WTSQueryUserToken successfully.");
            }
            result = DuplicateTokenEx(
                  hToken,
                  GENERIC_ALL_ACCESS,
                  ref sa,
                  (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                  (int)TOKEN_TYPE.TokenPrimary,
                  ref hDupedToken
               );
            if (!result)
            {
                Console.WriteLine("E: DuplicateTokenEx failed");
            }
            else
            {
                Console.WriteLine("C: DuplicateTokenEx successfully.");
            }
            IntPtr lpEnvironment = IntPtr.Zero;
            result = CreateEnvironmentBlock(out lpEnvironment, hDupedToken, false);
            if (!result)
            {
                Console.WriteLine("E: CreateEnvironmentBlock failed");
            }
            else
            {
                Console.WriteLine("C: CreateEnvironmentBlock successfully.");
            }

            result = CreateProcessAsUser(
                                 hDupedToken,
                                 app,
                                 "\""+app+"\" \""+cmdline+"\"",
                                 ref sa, ref sa,
                                 false, 0, IntPtr.Zero,
                                 path, ref si, ref pi);
            if (!result)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 2)
                {
                    result = CreateProcessAsUser(
                                 hDupedToken,
                                 Environment.SystemDirectory+"\\"+app,
                                 "\"" + app + "\" \"" + cmdline + "\"",
                                 ref sa, ref sa,
                                 false, 0, IntPtr.Zero,
                                 path, ref si, ref pi);
                    if (!result)
                    {
                        int err = Marshal.GetLastWin32Error();
                        string message = String.Format(" CreateProcessAsUser Error code: {0}", err);
                        Console.WriteLine("E:" + message);
                    }
                    else
                    {
                        Console.WriteLine("C: CreateProcessAsUser successfully.");
                    }
                }
            } else
            {
                Console.WriteLine("C: CreateProcessAsUser successfully.");
            }
            if (pi.hProcess != IntPtr.Zero)
                CloseHandle(pi.hProcess);
            if (pi.hThread != IntPtr.Zero)
                CloseHandle(pi.hThread);
            if (hDupedToken != IntPtr.Zero)
                CloseHandle(hDupedToken);
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessID;
            public Int32 dwThreadID;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }
        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }
        public const int GENERIC_ALL_ACCESS = 0x10000000;
        [DllImport("kernel32.dll", SetLastError = true,
            CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true,
            CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandle,
            Int32 dwCreationFlags,
            IntPtr lpEnvrionment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            Int32 dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            Int32 ImpersonationLevel,
            Int32 dwTokenType,
            ref IntPtr phNewToken);
        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(
            Int32 sessionId,
            out IntPtr Token);
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment,
            IntPtr hToken,
            bool bInherit);
    }
    class Program
    {
        [DllImport("kernel32")]
        public static extern void GetWindowsDirectory(StringBuilder WinDir, int count);
        [DllImport("kernel32")]
        public static extern void GetSystemDirectory(StringBuilder SysDir, int count);

        
        static void Main(string[] args)
        {
            switch (args.Length)
            {
                case 1 :
                    Interop.CreateProcess(args[0].ToString(), Environment.SystemDirectory, String.Empty);
                    break;
                case 2 :
                    Interop.CreateProcess(args[0].ToString(), Environment.SystemDirectory, args[1].ToString());
                    break;
                case 3 :
                    if (args[0].ToString() == "msgbox")
                    {
                        Interop.ShowMessageBox(@args[1].ToString(), @args[2].ToString());
                    }
                    break;
                default :
                    Console.WriteLine("");
                    Console.WriteLine("Session Transfer by @xiaopc <http://xpc.im/>");
                    Console.WriteLine("Make sure that it has SYSTEM permission!!!");
                    Console.WriteLine("");
                    Console.WriteLine("SessionTransfer (exec, [cmdline])");
                    Console.WriteLine("  exec     An executive program.");
                    Console.WriteLine("           ATTENTION: FILE EXTENSION NEEDED!!!");
                    Console.WriteLine("  cmdline  Parameters.");
                    Console.WriteLine("");
                    Console.WriteLine("  If you just want to send a meassge box ,try:");
                    Console.WriteLine("  SessionTransfer msgbox \"content\" \"title\"");
                    break;
            }

            System.Environment.Exit(0); 
        }
    }
}
