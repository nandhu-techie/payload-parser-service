using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Newtonsoft.Json;
using PktMonData;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace PayloadParserService
{
    public class TraceEvents
    {
        public static void TraceEventsMain()
        {
            string etlFilePath = Environment.GetEnvironmentVariable(PacketMonCommon.parserfilepath, EnvironmentVariableTarget.Machine) + "PktMon.etl";
            string wiresharkDissetorPath = Environment.GetEnvironmentVariable(PacketMonCommon.wiresharkInstallDirEnvVar, EnvironmentVariableTarget.Machine);

            using (var source = new ETWTraceEventSource(etlFilePath))
            {
                //var kernelParser = new KernelTraceEventParser(source);

                //// Subscribe to a particular Kernel event
                //kernelParser.ProcessStart += delegate (ProcessTraceData data) {
                //    string test = data.ToString();
                //};


                source.Dynamic.All += delegate (TraceEvent data)
                {
                    Console.WriteLine("GOT EVENT {0}", data);

                    var list = data.PayloadNames.ToList().Where(e => e == "Payload");
                    var testdata = data.PayloadByName("ComponentId");


                    // if (list.Count() == 1)
                    //{
                    foreach (var name in data.PayloadNames)
                    {
                        if (name == "Payload")
                        {
                            Byte[] payld = (Byte[])data.PayloadByName(name);

                            int originalPayloadSize = Convert.ToInt32(data.PayloadByName("OriginalPayloadSize"));

                            bool isNodata = PktMonDecodeData.TryGetDecodedPayload(payld, true, originalPayloadSize, PktMonData.WiresharkPacketType.Ethernet, out string decodedPayloadString, out int err);

                            string result = decodedPayloadString;
                            //Console.WriteLine(name + " -- " + data.PayloadByName(name));


                        }

                        if (name == "Description")
                        {
                            if (data.PayloadByName(name).ToString() == "49")
                            {
                                var test = data.PayloadByName(name);

                            }
                        }

                        if (name == "ComponentId" && data.PayloadByName(name).ToString() == "49")
                        {
                            var test = data.PayloadByName(name);
                        }

                    }
                    //}
                    //else
                    //{
                    //    //string result =
                    //}



                };
                source.Process();
            }

            //using (var source = new ETWTraceEventSource(etlFilePath))
            //{
            //    var parser = new DynamicTraceEventParser(source);
            //    // Set up the callbacks
            //    parser.All += delegate (TraceEvent data) {
            //        Console.WriteLine("GOT EVENT {0}", data);
            //    };
            //    source.Process(); // Invoke callbacks for events in the source
            //}

            //using (var traceLog = TraceLog.OpenOrConvert(etlFilePath))
            //{
            //    foreach (TraceEvent data in traceLog.Events)
            //    {
            //        Console.WriteLine("Got Event {0}", data);
            //    }
            //}
            //List<object> lst = new List<object>();
            //using (var source = new ETWTraceEventSource(etlFilePath))
            //{
            //    // Set up the callbacks
            //    source.Dynamic.All += delegate (TraceEvent data)
            //    {
            //        //lst.Add(new
            //        //{
            //        //    EventId = (int)data.ID,
            //        //    Level = data.Level,
            //        //    LoggerName = (String)data.PayloadByName("LoggerName"),
            //        //    //Message = (String)data.PayloadByName("Message")
            //        //});
            //        Console.WriteLine("GOT EVENT {0}", data.);

            //        XmlDocument doc = new XmlDocument();
            //        doc.LoadXml(data.ToString());

            //        string json = JsonConvert.SerializeXmlNode(doc);
            //        //source.ToString();
            //    };
            //    source.Process(); // Invoke callbacks for events in the source
            //}
        }
    }
}
