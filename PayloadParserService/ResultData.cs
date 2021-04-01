using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PayloadParserService
{
    //public class ResultData
    //{
    //    public DateTime EventTime { get; set; }
    //    public string Source { get; set; }
    //    public string Destination { get; set; }
    //    public string Protocol { get; set; }
    //    public string Message { get; set; }
    //    public string ComponentId { get; set; }
    //    public string ComponentDescription { get; set; }

    //    public EventInfo EventInfo{get;set;}

    //    public Dictionary<string,string> EventProperties { get; set; }

    //}

    public class WiresharkSummary
    {
        public string summary { get; set; }

        public string src_addr { get; set; }

        public string dst_addr { get; set; }

        public string protocol { get; set; }

    }

    public class ComponentInfo
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
    }

    //public class EventInfo
    //{
    //    public string EventType { get; set; }
    //    public string ProviderName { get; set; }
    //    public string ProviderGuid { get; set; }
    //    public string Timestamp { get; set; }
    //    public string EventID { get; set; }
    //    public string EventKeyword { get; set; }
    //    public string PacketCaptureType { get; set; }
    //    public string Opcode { get; set; }
    //    public string Channel { get; set; }
    //    public string ProcessorNumber { get; set; }
    //    public string ProcessID { get; set; }
    //    public string ThreadID { get; set; }
    //    public string Message { get; set; }
    //}
    public class Report
    {
        [JsonProperty("Event Time")]
        public DateTime EventTime { get; set; }
        public string Source { get; set; }
        public string Destination { get; set; }
        public string Protocol { get; set; }
        public string Message { get; set; }

        [JsonProperty("Component Id")]
        public string ComponentId { get; set; }
        [JsonProperty("Component Description")]
        public string ComponentDescription { get; set; }
        [JsonProperty("Event Type")]
        public string EventType { get; set; }
        [JsonProperty("Event Info")]
        public Dictionary<string, string> EventInfos { get; set; }
        [JsonProperty("Event Properties")]
        public Dictionary<string, string> EventPropertiesList { get; set; }
        public dynamic Layers { get; set; }
    }
  


    public enum TraceEventType
    {
        ETW = 1,
        WPP,
        TraceLog,
        Packet,
        PacketDrop
    }


    public enum PacketCaptureType
    {
        None = 0,
        PacketMon,
        Ndis
    }



}
