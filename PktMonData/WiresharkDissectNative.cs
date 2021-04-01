using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace PktMonData
{
    internal static class WiresharkDissectNative
    {
        [DllImport("kernel32.dll", EntryPoint = "SetDllDirectory", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool SetDllDirectory(string directory);

        [DllImport("wiresharkdissect.dll")]
        internal static extern int dissect(byte[] input,
            int input_len,
            [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder output,
            int output_len,
            bool detailed_json,
            int pkt_size,
            int encap_type,
            UInt64 time
        );
    }
}
