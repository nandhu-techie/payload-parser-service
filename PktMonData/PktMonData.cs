using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace PktMonData
{
    public class PktMonDecodeData
    {
        public Events Events { get; set; }

        public static bool TryGetDecodedPayload(Byte[] inputBytes, bool detailedJson, int originalPayloadSize,  WiresharkPacketType packetType, out string decodedString, out int err)
        {
            int output_len = 4096;
            StringBuilder json = new StringBuilder(output_len);

            decodedString = null;
            err = PacketMonCommon.ERROR_DLL_NOT_FOUND;
            try
            {
               
                //Check if the DLL is installed by Getting the Path
                string wiresharkDissectorPath = Environment.GetEnvironmentVariable(PacketMonCommon.wiresharkInstallDirEnvVar, EnvironmentVariableTarget.Machine);

                if (Directory.Exists(wiresharkDissectorPath))
                {
                    bool ret = WiresharkDissectNative.SetDllDirectory(wiresharkDissectorPath);

                    if (ret == false)
                    {
                        return false;
                    }

                    try
                    {
                        err = WiresharkDissectNative.dissect(inputBytes, inputBytes.Length, json, output_len, detailedJson, originalPayloadSize, (int)packetType, 0);

                        while (err == PacketMonCommon.ERROR_INSUFFICIENT_BUFFER)
                        {
                            output_len = output_len * 2;

                            json.EnsureCapacity(output_len);

                            err = WiresharkDissectNative.dissect(inputBytes, inputBytes.Length, json, output_len, detailedJson, originalPayloadSize, (int)packetType, 0);
                        }
                    }
                    catch (Exception ex)
                    {

                        decodedString = "Error : " + ex.Message.ToString()+ ex.InnerException.ToString();
                        return false;
                    }

                    if (err == 0)
                    {
                        decodedString = json.ToString();
                        return false;
                    }
                    else
                    {

                        return false;
                    }
                }
                else
                {

                    return false;
                }
            }
            catch (Exception ex)
            {

                decodedString =  "Error : " + ex.Message.ToString() + ex.InnerException.ToString(); 
                return false;
            }
        }

        static void Main()
        { }
    }

    public class Provider
    {
        [XmlAttribute(AttributeName = "Guid")]
        public string Guid { get; set; }
        [XmlAttribute(AttributeName = "Name")]
        public string Name { get; set; }
    }

    [XmlRoot(ElementName = "TimeCreated")]
    public class TimeCreated
    {
        [XmlAttribute(AttributeName = "SystemTime")]
        public DateTime SystemTime { get; set; }
    }

    [XmlRoot(ElementName = "Correlation")]
    public class Correlation
    {
        [XmlAttribute(AttributeName = "ActivityID")]
        public string ActivityID { get; set; }
    }

    [XmlRoot(ElementName = "Execution")]
    public class Execution
    {
        [XmlAttribute(AttributeName = "ProcessID")]
        public string ProcessID { get; set; }
        [XmlAttribute(AttributeName = "ThreadID")]
        public string ThreadID { get; set; }
        [XmlAttribute(AttributeName = "ProcessorID")]
        public string ProcessorID { get; set; }
        [XmlAttribute(AttributeName = "KernelTime")]
        public string KernelTime { get; set; }
        [XmlAttribute(AttributeName = "UserTime")]
        public string UserTime { get; set; }
    }

    [XmlRoot(ElementName = "System")]
    public class System
    {
        [XmlElement(ElementName = "Provider")]
        public Provider Provider { get; set; }
        [XmlElement(ElementName = "EventID")]
        public string EventID { get; set; }
        [XmlElement(ElementName = "Version")]
        public string Version { get; set; }
        [XmlElement(ElementName = "Level")]
        public string Level { get; set; }
        [XmlElement(ElementName = "Task")]
        public string Task { get; set; }
        [XmlElement(ElementName = "Opcode")]
        public string Opcode { get; set; }
        [XmlElement(ElementName = "Keywords")]
        public string Keywords { get; set; }
        [XmlElement(ElementName = "TimeCreated")]
        public TimeCreated TimeCreated { get; set; }
        [XmlElement(ElementName = "Correlation")]
        public Correlation Correlation { get; set; }
        [XmlElement(ElementName = "Execution")]
        public Execution Execution { get; set; }
        [XmlElement(ElementName = "Channel")]
        public string Channel { get; set; }
        [XmlElement(ElementName = "Computer")]
        public string Computer { get; set; }
    }

    [XmlRoot(ElementName = "Data")]
    public class Data
    {
        [XmlAttribute(AttributeName = "Name")]
        public string Name { get; set; }
        [XmlText]
        public string Text { get; set; }
    }

    [XmlRoot(ElementName = "EventData")]
    public class EventData
    {
        [XmlElement(ElementName = "Data")]
        public List<Data> Data { get; set; }
    }

    [XmlRoot(ElementName = "EventName")]
    public class EventName
    {
        [XmlAttribute(AttributeName = "xmlns")]
        public string Xmlns { get; set; }
        [XmlText]
        public string Text { get; set; }
    }

    [XmlRoot(ElementName = "RenderingInfo")]
    public class RenderingInfo
    {
        [XmlElement(ElementName = "Opcode")]
        public string Opcode { get; set; }
        [XmlElement(ElementName = "Provider")]
        public string Provider { get; set; }
        [XmlElement(ElementName = "EventName")]
        public EventName EventName { get; set; }
        [XmlAttribute(AttributeName = "Culture")]
        public string Culture { get; set; }
        [XmlElement(ElementName = "Level")]
        public string Level { get; set; }
        [XmlElement(ElementName = "Keywords")]
        public Keywords Keywords { get; set; }
        [XmlElement(ElementName = "Message")]
        public string Message { get; set; }
    }

    [XmlRoot(ElementName = "ExtendedTracingInfo")]
    public class ExtendedTracingInfo
    {
        [XmlElement(ElementName = "EventGuid")]
        public string EventGuid { get; set; }
        [XmlAttribute(AttributeName = "xmlns")]
        public string Xmlns { get; set; }
    }

    [XmlRoot(ElementName = "Event")]
    public class Event
    {
        [XmlElement(ElementName = "System")]
        public System System { get; set; }
        [XmlElement(ElementName = "EventData")]
        public EventData EventData { get; set; }
        [XmlElement(ElementName = "RenderingInfo")]
        public RenderingInfo RenderingInfo { get; set; }
        [XmlElement(ElementName = "ExtendedTracingInfo")]
        public ExtendedTracingInfo ExtendedTracingInfo { get; set; }
        [XmlAttribute(AttributeName = "xmlns")]
        public string Xmlns { get; set; }
        [XmlElement(ElementName = "ProcessingErrorData")]
        public ProcessingErrorData ProcessingErrorData { get; set; }
        [XmlElement(ElementName = "BinaryEventData")]
        public string BinaryEventData { get; set; }
    }

    [XmlRoot(ElementName = "ProcessingErrorData")]
    public class ProcessingErrorData
    {
        [XmlElement(ElementName = "ErrorCode")]
        public string ErrorCode { get; set; }
        [XmlElement(ElementName = "DataItemName")]
        public string DataItemName { get; set; }
        [XmlElement(ElementName = "EventPayload")]
        public string EventPayload { get; set; }
    }

    [XmlRoot(ElementName = "Keywords")]
    public class Keywords
    {
        [XmlElement(ElementName = "Keyword")]
        public string Keyword { get; set; }
    }

    [XmlRoot(ElementName = "Events")]
    public class Events
    {
        [XmlElement(ElementName = "Event")]
        public List<Event> Event { get; set; }
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
    /// WireharkPacketType maps to definitions for Packet Type in wiretap/wtap.h in wireshark
    /// </summary>
    public enum WiresharkPacketType
    {
        Unknown = 0,    //WTAP_ENCAP_UNKNOWN
        Ethernet = 1,   //WTAP_ENCAP_ETHERNET
        Wifi = 20,      //WTAP_ENCAP_IEEE_802_11,
        IP = 7          //WTAP_ENCAP_RAW_IP
    }
}
