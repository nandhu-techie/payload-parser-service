using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Timers;
using PktMonData;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.Diagnostics.Tracing;
using System.Net;
using System.Text.RegularExpressions;

namespace PayloadParserService
{
    public partial class Service1 : ServiceBase
    {
        Timer timer = new Timer();
        string outputText = "";

        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                string wiresharkDissetorPath = Environment.GetEnvironmentVariable(PacketMonCommon.wiresharkInstallDirEnvVar, EnvironmentVariableTarget.Machine);
                string etlFilePath = Environment.GetEnvironmentVariable(PacketMonCommon.parserfilepath, EnvironmentVariableTarget.Machine) + "PktMon.etl";
                this.ProcessData(etlFilePath, wiresharkDissetorPath);

                timer.Elapsed += new ElapsedEventHandler(OnElapsedTime);
                timer.Interval = 5000; //number in miliseconds  
                timer.Enabled = true;
            }
            catch (Exception ex)
            {
                WriteToFile(DateTime.Now + "Error  : " + ex.Message.ToString() + ex.InnerException.ToString(), "Error");
            }
        }

        public void ProcessData(string etlFilePath, string wiresharkDissetorPath)
        {
            try
            {
                List<Report> resultList = new List<Report>();
                List<ComponentInfo> components = new List<ComponentInfo>();

                using (var source = new ETWTraceEventSource(etlFilePath))
                {
                    source.Dynamic.All += delegate (TraceEvent data)
                    {
                        Report report = new Report();

                        TraceEventType eventType = TraceEventType.ETW;

                        Dictionary<string, string> eInfo = new Dictionary<string, string>();
                        eInfo.Add("Event Type", GetEventType(data, GetPacketCaptureType(data), eventType));
                        eInfo.Add("Event ID", data.ID.ToString());
                        eInfo.Add("Event Keyword", SetEventName((int)data.Keywords));
                        eInfo.Add("Provider Name", data.ProviderName.ToString());
                        eInfo.Add("Provider Guid", data.ProviderGuid.ToString());
                        eInfo.Add("Timestamp", data.TimeStamp.ToString());
                        eInfo.Add("Opcode", data.Opcode.ToString());
                        eInfo.Add("Level", data.Level.ToString());
                        eInfo.Add("Channel", data.Channel.ToString());
                        eInfo.Add("Processor Number", data.ProcessorNumber.ToString());
                        eInfo.Add("Process ID", data.ProcessID.ToString());
                        eInfo.Add("Thread ID", data.ThreadID.ToString());

                        Dictionary<string, string> eProperties = new Dictionary<string, string>();

                        Dictionary<string, string> layers = new Dictionary<string, string>();


                        report.EventTime = data.TimeStamp;
                        report.EventType = GetEventType(data, GetPacketCaptureType(data), eventType);

                        var list = data.PayloadNames.ToList().Where(e => e == "Payload");

                        if (data.PayloadNames.Length == 4)
                        {
                            ComponentInfo componentInfo = new ComponentInfo();
                            foreach (var item in data.PayloadNames)
                            {
                                if (item == "Id")
                                {
                                    componentInfo.Id = data.PayloadByName("Id").ToString();
                                }
                                else if (item == "Type")
                                {
                                    componentInfo.Type = data.PayloadByName("Type").ToString();

                                }
                                else if (item == "Name")
                                {
                                    componentInfo.Name = data.PayloadByName("Name").ToString();

                                }
                                else if (item == "Description")
                                {
                                    componentInfo.Description = data.PayloadByName("Description").ToString();

                                }
                            }
                            components.Add(componentInfo);

                        }
                        else
                        {
                            foreach (var item in data.PayloadNames)
                            {
                                Type tp = data.PayloadByName(item).GetType();
                                string value = "";
                                if (tp.Equals(typeof(byte[])))
                                {
                                    byte[] bytearray;
                                    bytearray = (byte[])(data.PayloadByName(item));
                                    value = BitConverter.ToString(bytearray);
                                }
                                else
                                {
                                    if (item == "DestinationIP" || item == "SourceIP")
                                    {
                                        value = new IPAddress(BitConverter.GetBytes((int)data.PayloadByName(item)).ToArray()).ToString();
                                    }
                                    else
                                    {
                                        value = data.PayloadByName(item).ToString();
                                    }
                                }
                                string keyName = Regex.Replace(item, "[A-Z]", " $0").Trim();
                                eProperties.Add(keyName, value);
                            }
                        }
                        if (list.Count() == 1)
                        {
                            Byte[] payld = (Byte[])data.PayloadByName("Payload");
                            int originalPayloadSize =Convert.ToInt32( data.PayloadByName("OriginalPayloadSize"));
                            bool isNodata = PktMonDecodeData.TryGetDecodedPayload( payld, false, originalPayloadSize, PktMonData.WiresharkPacketType.Ethernet, out string decodedPayloadString, out int err);
                            if (!isNodata)
                            {
                                WiresharkSummary wiresharkSummary = Newtonsoft.Json.JsonConvert.DeserializeObject<WiresharkSummary>(decodedPayloadString);
                                report.Message = wiresharkSummary.summary;
                                report.Source = wiresharkSummary.src_addr;
                                report.Destination = wiresharkSummary.dst_addr;
                                report.Protocol = wiresharkSummary.protocol;
                                report.ComponentId = data.PayloadByName("ComponentId").ToString();

                                // get full data
                                PktMonDecodeData.TryGetDecodedPayload( payld, true, originalPayloadSize, PktMonData.WiresharkPacketType.Ethernet, out string decodPayloadString, out int er);
                                JObject rss = JObject.Parse(decodPayloadString);
                                JObject results = JsonConvert.DeserializeObject<JObject>(rss["_source"]["layers"].ToString());
                                var jsonvalue = JObject.Parse(decodPayloadString);
                              
                                report.Layers = jsonvalue;
                                report.EventInfos = eInfo;
                                report.EventPropertiesList = eProperties;
                                resultList.Add(report);
                            }
                            else
                            {
                                WriteToFile(DateTime.Now + decodedPayloadString, "Error");
                            }
                        }
                        //else
                        //{
                        //    if (data.FormattedMessage != null)
                        //    {
                        //        eInfo.Add(GetEventInfo("Message", data.FormattedMessage.ToString()));
                        //        report.Message = data.FormattedMessage;
                        //        report.EventInfos = eInfo;
                        //        report.EventPropetiesList = eProperties;
                        //        resultList.Add(report);
                        //    }

                        //}
                    };
                    source.Process();
                }

                resultList.ForEach((itm) =>
                {
                    int index = resultList.IndexOf(itm);
                    var componentInfo = components.Where(x => x.Id == itm.ComponentId);
                    if (componentInfo.ToList().Count > 0)
                    {
                        itm.ComponentDescription = componentInfo.ToList()[0].Description;
                        resultList[index].ComponentDescription = itm.ComponentDescription;
                    }
                });
                outputText = JsonConvert.SerializeObject(resultList, Formatting.Indented);
            }
            catch (Exception ex)
            {
                WriteToFile(DateTime.Now + "Error  : " + ex.Message.ToString() + ex.InnerException.ToString(), "Error");
            }

        }
        public List<JObject> GetPacketList(JObject results)
        {
            List<JObject> packetlist = new List<JObject>();
            try
            {
                foreach (dynamic item in results)
                {
                    packetlist.Add(GetNode(item));
                }
            }
            catch (Exception ex)
            {

                return null;
            }
            return packetlist;
        }
        public JObject GetNode(dynamic data)
        {
            dynamic type = data.GetType().Name;
            int count = 0;
            if (type.Contains("KeyValuePair"))
            {
                count = ((KeyValuePair<string, JToken>)data).Value.ToList().Count;
            }
            else
            {
                count = ((JProperty)data).Value.ToList().Count;
            }
            JObject jObject = new JObject();
            if (count >= 1)
            {
                List<JObject> listObj = new List<JObject>();
                foreach (var item in data.Value)
                {
                    JObject Jobj = this.GetNode(item);
                    listObj.Add(Jobj);
                }
                if (type.Contains("KeyValuePair"))
                {
                    jObject = new JObject(new JProperty(data.Key, listObj));
                }
                else
                {
                    jObject = new JObject(new JProperty(data.Name, listObj));
                }
            }
            else
            {
                jObject = GetPacketObject(data);
            }
            return jObject;
        }

       


        public JObject GetPacketObject(dynamic item)
        {
            dynamic type = item.GetType().Name;
            string Key = type.Contains("KeyValuePair") ? item.Key : item.Name;
            JObject packetdetail;
            try
            {
                JObject detail = new JObject(
                  new JProperty("label", Key),
                        new JProperty("value", item.Value.ToString())
                );
                JObject dt = new JObject(
                     new JProperty("Details", detail),
                     new JProperty("type", "table")
                    );
                packetdetail = new JObject(
                new JProperty("data", dt)
                );
            }
            catch (Exception ex)
            {
                return null;
            }
            return packetdetail;
        }

        protected override void OnStop()
        {
            // stop service
            WriteToFile(outputText);
        }

        public void WriteToFile(string Message, string MsgType = null)
        {
            string path = Environment.GetEnvironmentVariable(PacketMonCommon.parserfilepath, EnvironmentVariableTarget.Machine);

            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            if (MsgType == "Error")
            {
                string filepath = path + "Error.txt";
                if (!File.Exists(filepath))
                {
                    // Create a file to write to.   
                    using (StreamWriter sw = File.CreateText(filepath))
                    {
                        sw.WriteLine(Message);
                    }
                }
                else
                {
                    using (StreamWriter sw = File.AppendText(filepath))
                    {
                        sw.WriteLine(Message);
                    }
                }
            }
            else
            {
                string filepath = path + "PktMon.txt";
                if (!File.Exists(filepath))
                {
                    // Create a file to write to.   
                    using (StreamWriter sw = File.CreateText(filepath))
                    {
                        sw.WriteLine(Message);
                    }
                }
                else
                {
                    // Delete existing file
                    File.Delete(filepath);

                    // Create a file to write to.   
                    using (StreamWriter sw = File.CreateText(filepath))
                    {
                        sw.WriteLine(Message);
                    }
                }
            }

        }

        public PacketCaptureType GetPacketCaptureType(TraceEvent eventInfo)
        {
            PacketCaptureType captureType = PacketCaptureType.None;

            if (eventInfo.ProviderGuid.Equals(PacketMonCommon.PacketMonGuid))
            {
                if ((int)eventInfo.ID == PacketMonCommon.PktMonEvtFramePayload || (int)eventInfo.ID == PacketMonCommon.PktMonEvtFrameDropPayload || (int)eventInfo.ID == PacketMonCommon.PktMonEvtFrameDupDropPayload)
                {
                    captureType = PacketCaptureType.PacketMon;
                }
            }
            else if (eventInfo.ProviderGuid.Equals(PacketMonCommon.NdisCaptureGuid))
            {
                if ((((ulong)eventInfo.Keywords &
                    (PacketMonCommon.NDISCAP_KW_PACKET_START | PacketMonCommon.NDISCAP_KW_PACKET_END)) == (PacketMonCommon.NDISCAP_KW_PACKET_START | PacketMonCommon.NDISCAP_KW_PACKET_END)) &&
                    ((int)eventInfo.ID == PacketMonCommon.NdisCapEvtPacket || (int)eventInfo.ID == PacketMonCommon.NdisCapEvtVmsPacket))
                {
                    captureType = PacketCaptureType.Ndis;
                }
            }
            else
            {
                return captureType;
            }
            return captureType;

        }

        private string GetEventType(TraceEvent e, PacketCaptureType captureType, TraceEventType eventType)
        {

            if (captureType == PacketCaptureType.PacketMon || captureType == PacketCaptureType.Ndis)
            {
                if (IsPacketDrop(e) || IsPacketDuplicateDrop(e))
                {
                    return TraceEventType.PacketDrop.ToString();
                }
                else
                {
                    return TraceEventType.Packet.ToString();
                }
            }
            else
            {
                return eventType.ToString();
            }
        }
        public string eventname;
        public string SetEventName(int key)
        {
            switch (key)
            {
                case (int)Eventkeyword.None:
                    eventname = Eventkeyword.None.ToString();
                    break;
                case (int)Eventkeyword.Rundown:
                    eventname = Eventkeyword.Rundown.ToString();
                    break;
                case (int)Eventkeyword.Nblparsed:
                    eventname = Eventkeyword.Nblparsed.ToString();
                    break;
                case (int)Eventkeyword.Payload:
                    eventname = Eventkeyword.Payload.ToString();
                    break;
                default:
                    eventname = Eventkeyword.None.ToString();
                    break;
            }
            return eventname;
        }

        //public EventInfo GetEventInfo(string label, string value)
        //{
        //    EventInfo eventInfo = new EventInfo();
        //    Detail detail = new Detail();
        //    Data dt = new Data();
        //    detail.label = label;
        //    detail.value = value;
        //    dt.Details = detail;
        //    dt.type = "table";
        //    eventInfo.data = dt;
        //    return eventInfo;
        //}

        //public EventProperties GetEventProperties(string label, string value)
        //{
        //    EventProperties eventProperties = new EventProperties();
        //    Detail detail = new Detail();
        //    Data dt = new Data();
        //    detail.label = label;
        //    detail.value = value;
        //    dt.Details = detail;
        //    dt.type = "table";
        //    eventProperties.data = dt;
        //    return eventProperties;
        //}

     //   public List<JObject> GetPacketInfo(dynamic data)
     //   {

     //       List<JObject> packetlist = new List<JObject>();
     //       foreach (var item in data.Value)
     //       {
     //           if (((JToken)item).Parent.Count > 0)
     //           {

     //               foreach (var itm in ((JToken)item).Parent)
     //               {

     //               }
     //           }
     //           else
     //           {
     //               JObject packetdetail;
     //               JObject detail = new JObject(
     //                 new JProperty("label", item.Name),
     //new JProperty("value", item.Value)
     //               );
     //               JObject dt = new JObject(
     //                    new JProperty("Details", detail),
     //                    new JProperty("type", "table")
     //                   );
     //               packetdetail = new JObject(
     //               new JProperty("data", dt)
     //               );
     //               packetlist.Add(packetdetail);

     //           }

     //       }

     //       return packetlist;
     //   }

        public List<JObject> GetPacketDetails(dynamic item)
        {
            List<JObject> packetlist = new List<JObject>();

            while (((JToken)item).Parent.Count > 0)
            {
                JObject packetdetail;
                JObject detail = new JObject(
                  new JProperty("label", item.Name),
                         new JProperty("value", item.Value)
                );
                JObject dt = new JObject(
                     new JProperty("Details", detail),
                     new JProperty("type", "table")
                    );
                packetdetail = new JObject(
                new JProperty("data", dt)
                );
                packetlist.Add(packetdetail);

            }

            return packetlist;
        }
        static bool IsPacketDrop(TraceEvent e)
        {
            return (int)e.ID == PacketMonCommon.PktMonEvtFrameDropPayload;
        }

        static bool IsPacketDuplicateDrop(TraceEvent e)
        {
            return (int)e.ID == PacketMonCommon.PktMonEvtFrameDupDropPayload;
        }


        private void OnElapsedTime(object source, ElapsedEventArgs e)
        {
            // service recall
        }

        public enum PktMonPacketType
        {
            Unknown = 0,
            Ethernet,
            Wifi,
            IP,
            HTTP
        }

        /// <summary>
        /// WireharkPacketType maps to definitions for Packet Type 
        /// </summary>
        public enum WiresharkPacketType
        {
            Unknown = 0,    //WTAP_ENCAP_UNKNOWN
            Ethernet = 1,   //WTAP_ENCAP_ETHERNET
            Wifi = 20,      //WTAP_ENCAP_IEEE_802_11,
            IP = 7          //WTAP_ENCAP_RAW_IP
        }

        public enum Eventkeyword
        {
            None = 0,
            Rundown = 2,
            Nblparsed = 4,
            Payload = 16
        }
        public enum EtherType
        {
            IPv4 = 2048,
            ARP = 2054
        }
    }


}
