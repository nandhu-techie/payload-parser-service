using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PayloadParserService
{

    public static class NativeConstants
    {
        public const int S_OK = 0;
        public const int S_FALSE = 1;
        public const uint E_FAIL = 0x80004005;
        public const uint E_NOINTERFACE = 0x80004002;

        public const uint STATUS_BUFFER_TOO_SMALL = 0xC0000023;

        public const int SEVERITY_SUCCESS = 0;
        public const int SEVERITY_ERROR = 1;
        public const int FACILITY_ITF = 4;
        public const int FACILITY_WIN32 = 7;

        public const uint FACILITY_NT_BIT = 0x10000000;

        public const int ERROR_NOT_FOUND = 1168;

        public const ushort EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID = 0x0001;
        public const ushort EVENT_HEADER_EXT_TYPE_SID = 0x0002;
        public const ushort EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL = 0x000B;

        // used as dwFlags parameter in FormatMessage
        public const uint FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
        public const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
        public const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
        public const uint FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000;
        public const uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
        public const uint FORMAT_MESSAGE_FROM_STRING = 0x00000400;
    }
}
