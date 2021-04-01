using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PktMonData
{
    public static class PacketMonCommon
    {
        #region CONSTANTS

        public static readonly Guid PacketMonGuid = Guid.Parse("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac");
        public static readonly Guid NdisCaptureGuid = Guid.Parse("2ED6006E-4729-4609-B423-3EE7BCD678EF");

        public static readonly int PktMonEvtFramePayload = 160;
        public static readonly int PktMonEvtFrameDropPayload = 170;
        public static readonly int PktMonEvtFrameDupDropPayload = 240;

        public static readonly int PktMonEvtL5PayloadIpv4 = 200;
        public static readonly int PktMonEvtL5PayloadDropIpv4 = 210;
        public static readonly int PktMonEvtL5PayloadIpv6 = 220;
        public static readonly int PktMonEvtL5PayloadDropIpv6 = 230;
        public static readonly int PktMonEvtComponentInfo = 20;

        public static readonly int NdisCapEvtPacket = 1001;
        public static readonly int NdisCapEvtVmsPacket = 1003;

        public static readonly ulong NDISCAP_KW_PACKET_START = 0x0000000040000000;
        public static readonly ulong NDISCAP_KW_PACKET_END = 0x0000000080000000;

        public static readonly ulong NDISCAP_KW_MEDIA_WIRELESS_WAN = 0x200;
        public static readonly ulong NDISCAP_KW_MEDIA_NATIVE_802_11 = 0x10000;

        public static readonly int ERROR_INSUFFICIENT_BUFFER = 122;
        public static readonly int ERROR_DLL_NOT_FOUND = 2;

        public static readonly string wiresharkInstallDirEnvVar = "WIRESHARK_DISSECT_DIR";

        public static readonly string parserfilepath = "PARSER_FILES_PATH";


        //This needs to be updated for an update in the wireshark Dissector version
        public static readonly string wiresharkInstallLocation = "https://github.com/kreypour/wireshark/releases/download/1.0.0.5/wiresharkdissect.exe";

        #endregion

        #region METHODS
        //public static string GetPropertyValue(uint propertyIndex, TraceEventInfoCPtr tei, EventRecordCPtr e, Timestamp timestamp, ParseTdhContext context, IEventMetadataInfoSource2 eventMetaDataInfoSource = null)
        //{
        //    UnmanagedString mapName = tei.GetMapForProperty(propertyIndex);
        //    EventMapInfoCPtr eventMapInfo;

        //    if (!mapName.IsEmpty)
        //    {
        //        unsafe
        //        {
        //            EVENT_MAP_INFO* pEventMapInfo;
        //            uint cbEventMapInfo;
        //            if (eventMetaDataInfoSource != null)
        //            {
        //                int hresult = eventMetaDataInfoSource.GetEventMapInformation(tei.ProviderID, mapName, out pEventMapInfo, out cbEventMapInfo);
        //                if (hresult == 0)
        //                {
        //                    eventMapInfo = new EventMapInfoCPtr(pEventMapInfo);
        //                }
        //                else
        //                {
        //                    eventMapInfo = new EventMapInfoCPtr();
        //                }
        //            }
        //        }
        //    }

        //    return TdhHelper.GetStringForPropertyAtIndex(e, timestamp, tei, propertyIndex, context, CultureInfo.CurrentCulture, eventMapInfo);
        //}
        #endregion
    }
}
