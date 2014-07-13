using SecureSocketProtocol2;
using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.SocksProxy;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using SecureSocketProtocol2.Misc;
using System.Threading;
using SecureSocketProtocol2.Network.Messages;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using SecureSocketProtocol2.Compressions;
using Client.Messages;
using SecureSocketProtocol2.Plugin;
using SecureSocketProtocol2.Network.Protections;
using SecureSocketProtocol2.Network.Protections.Encryption;
using SecureSocketProtocol2.Network.Protections.Masks;
using System.Windows.Forms;
using Client.LiteCode;
using SecureSocketProtocol2.Attributes;
using SecureSocketProtocol2.Network.Protections.Compression;
using SecureSocketProtocol2.Network.RootSocket;
using SecureSocketProtocol2.Cache;
using SecureSocketProtocol2.Cache.CacheMethods;

namespace Client
{
    class Program : SSPClient
    {
        static Program prog;
        static ulong Received = 0;
        static int PacketsPerSec = 0;
        static Stopwatch speedSW = Stopwatch.StartNew();

        public Program()
            : base(new ClientProperties("127.0.0.1", 444, typeof(TestChannel), new object[0], new byte[]
            { //private key, can be any size you want
                80, 118, 131, 114, 195, 224, 157, 246, 141, 113,
                186, 243, 77, 151, 247, 84, 70, 172, 112, 115,
                112, 110, 91, 212, 159, 147, 180, 188, 143, 251,
                218, 155
            }, new Stream[]
            {//key files
                //new FileStream(@"C:\Users\Anguis\Desktop\lel.png", FileMode.Open, FileAccess.Read, FileShare.Read)
            }, null, 30000,//login
               "Dergan", "Hunter:)"))
        {
            
        }

        static void Main(string[] args)
        {
            /*byte[] data = new byte[] { 1,2,3,4,5,6,7,8,9 };

            MemoryStream InStream = new MemoryStream();
            MemoryStream OutStream = new MemoryStream();

            ICache cache = new SimpleCache(5000000);
            cache.Cache(data, 0, data.Length, InStream);
            cache.Decache(InStream.ToArray(), 0, (int)InStream.Length, OutStream);

            WopEncryption wopEncryption = new WopEncryption(new ulong[] {
                861335890, 388626021, 404588533, 738562051, 143466081,
                813679996, 890571662, 823294427, 135787739, 421508041,
                841473000, 552393879, 397881016, 459668250, 512708703,
                311855623
            },
            new uint[] {
                921772746, 666327786, 817602825, 400586423, 376646580,
                754874742, 178650796, 973149794, 308786223, 962247449,
                927153850, 989149359, 501229639, 219045145, 331863585,
                318046295, 
            });

            byte[] lolz = new byte[200000];
            Stopwatch sw = Stopwatch.StartNew();
            wopEncryption.Encrypt(lolz, 0, lolz.Length);
            sw.Stop();

            CacheStream cache = new CacheStream();
            CacheStream decache = new CacheStream();
            while (true)
            {
                NetworkPayloadWriter npw = new NetworkPayloadWriter();
                byte[] data = new byte[65535];
                //new Random().NextBytes(data);
                npw.WriteBytes(data);
                Stopwatch sw = Stopwatch.StartNew();
                byte[] Cached = new byte[0];
                uint CachedSize = cache.Write(npw, ref Cached);

                if (CachedSize > 0)
                {
                    byte[] DeCached = new byte[0];
                    int length = decache.Read(Cached, Connection.HEADER_SIZE, CachedSize, ref DeCached);
                }

                sw.Stop();
                Console.WriteLine("Cache speed: " + sw.ElapsedMilliseconds + "msec" + ", cache success:" + (CachedSize>0));
                Thread.Sleep(500);
            }*/

            /*FileStream stream = new FileStream("./PayloadMasker.dat", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
            if (stream.Length == 0)
            {
                Stopwatch sw2 = Stopwatch.StartNew();
                PayloadMasker.CreateMaskTable(37483782, 4, stream);
                sw2.Stop();
                Console.WriteLine("Generate completed in: " + sw2.Elapsed.Hours.ToString("D2") + ":" +  sw2.Elapsed.Minutes.ToString("D2") + ":" +  sw2.Elapsed.Seconds.ToString("D2"));
            }
            stream.Position = 0;
            PayloadMasker mask = new PayloadMasker(stream);
            byte[] orgCode = new byte[]
            {
                117, 91, 62, 113, 99, 116, 101, 63, 17, 68, 225, 230, 242, 10, 1, 117, 186, 120, 43, 200,
                114, 200, 100, 105, 235, 89, 9, 25, 219, 244, 114, 106, 195, 96, 117, 141, 109, 107, 125, 254,
                25, 225, 19, 81, 52, 204, 26, 191, 89, 3, 227, 192, 66, 100, 196, 187, 124, 186, 89, 231,
                200, 174, 192, 167, 233, 67, 13, 201, 209, 20, 204, 178, 109, 94, 71, 105, 71, 200, 48, 110,
                242, 38, 174, 227, 32, 117, 215, 58, 86, 135, 231, 109, 109, 86, 243, 186, 123, 164, 175, 37,
                147, 208, 158, 216, 87, 50, 23, 134, 109, 250, 202, 190, 43, 220, 181, 141, 31, 192, 145, 96,
                210, 75, 28, 116, 176, 227, 226, 88, 189, 123, 27, 205, 172, 226, 4, 229, 246, 81, 190, 37,
                19, 66, 20, 242, 15, 222, 63, 63, 212, 105, 73, 36, 247, 40, 51, 65, 210, 252, 40, 199,
                138, 64, 24, 154, 198, 212, 103, 97, 220, 182, 3, 20, 222, 94, 32, 21, 84, 195, 11, 168,
                12, 148, 231, 136, 55, 249, 100, 42, 205, 34, 159, 240, 26, 109, 54, 74, 48, 18, 99, 63,
                164, 84, 153, 222, 177, 10, 206, 247, 248, 166, 123, 97, 246, 41, 232, 153, 128, 47, 24, 161,
                6, 8, 195, 209, 234, 98, 97, 82, 214, 187, 16, 2, 71, 33, 67, 22, 30, 12, 213, 231,
                17, 150, 20, 189, 122, 16, 0, 217, 137, 226, 238, 119, 96, 6, 40, 108, 102, 145, 145, 26,
                23, 158, 0, 38, 138, 223, 80, 192, 152, 162, 103, 137, 107, 134, 132, 209, 246, 28, 163, 170,
                106, 132, 217, 198, 225, 43, 244, 159, 143, 125, 238, 114, 115, 207, 47, 9, 110, 208, 254, 116,
                53, 148, 225, 103, 172, 28, 191, 20, 115, 197, 188, 186, 112, 243, 143, 69, 78, 80, 144, 101,
                214, 250, 150, 174, 150, 189, 140, 105, 119, 228, 51, 62, 166, 126, 181, 214, 66, 63, 137, 221,
                208, 14, 76, 202, 76, 179, 153, 149, 8, 181, 60, 188, 177, 222, 78, 204, 57, 221, 239, 97,
                105, 78, 75, 240, 106, 214, 121, 127, 44, 165, 63, 8, 232, 203, 235, 132, 236, 108, 21, 38,
                219, 184, 111, 89, 203, 160, 73, 212, 101, 82, 36, 229, 222, 171, 49, 152, 0, 223, 66, 200,
                245, 93, 207, 97, 228, 87, 148, 91, 216, 67, 226, 13, 202, 46, 99, 174, 199, 107, 168, 192,
                28, 33, 174, 106, 27, 129, 104, 30, 34, 216, 253, 210, 32, 0, 227, 222, 56, 109, 72, 150,
                25, 182, 182, 104, 165, 193, 11, 49, 193, 143, 53, 21, 208, 109, 212, 110, 106, 89, 46, 46,
                222, 157, 254, 103, 9, 242, 43, 66, 168, 117, 12, 139, 127, 65, 178, 143, 212, 233, 171, 250,
                8, 32, 236, 6, 237, 36, 19, 230, 182, 71, 163, 123, 176, 170, 7, 214, 84, 204, 161, 205
            };
            uint offset = 0;
            uint length = (uint)orgCode.Length;
            PacketHeader header = new PacketHeader(null);

            int speed = 0;
            Stopwatch sw = Stopwatch.StartNew();
            while (true)
            {
                mask.Encode(ref orgCode, ref offset, ref length, ref header);
                mask.Decode(ref orgCode, ref offset, ref length, ref header);
                speed += orgCode.Length;

                if (sw.ElapsedMilliseconds >= 1000)
                {
                    Console.WriteLine("Speed: " +Math.Round(((float)speed / 1000F / 1000F), 2));
                    speed = 0;
                    sw = Stopwatch.StartNew();
                }
            }*/
            
            //try
            {
                //EncryptionTest();
                while(true)
                prog = new Program();
            } //catch(Exception ex)
            {
                //Console.WriteLine(ex.Message);
            }
            Process.GetCurrentProcess().WaitForExit();
        }

        private string DelegateCallbackTest(string Test)
        {
            return "A message from the private method!";
        }

        public override void onClientConnect()
        {
            Console.WriteLine("Virtual IP: " + base.VirtualIP);
            Console.Title = "SSP2 Client - ClientId:" + base.ClientId.ToString().Substring(0, 10) + "... - VritualIP:" + base.VirtualIP;
            Console.WriteLine("Connected");
            base.MessageHandler.AddMessage(typeof(TestMessage), "TEST_MESSAGE");
            ISharedTest SharedTest = SharedTest = base.GetSharedClass<ISharedTest>("SharedTest");

            /*string ResolvedDns = base.ResolveDns("TestRootSocket");
            if (ResolvedDns.Length == 0)
            {
                base.RegisterDns("TestRootSocket");
                return;
            }

            //peer found, connect to it
            Console.WriteLine("Connecting to peer " + ResolvedDns);
            Peer peer = new Peer();
            PeerErrorCode errorCode = base.ConnectToPeer(ResolvedDns, peer);

            while (true)
            {
                peer.SendMessage(new TestMessage());
                Thread.Sleep(1);
            }
            return;*/

            Benchmark BenchLiteCode = new Benchmark();
            int speedy = 0;
            while (false)
            {
                BenchLiteCode.Bench(new BenchCallback(() =>
                {
                    //send server our private method, now the server can call our private method ;)
                    //SharedTest.DelegateTest(new Callback<string>(DelegateCallbackTest));
                    SharedTest.SendByteArray(new byte[65535]);
                }));

                if(BenchLiteCode.PastASecond)
                {
                    Console.WriteLine("Call Speed: " + BenchLiteCode.SpeedPerSec + ", Speed: " + Math.Round(((float)speedy / 1000F) / 1000F, 2) + "MBps ");
                    speedy = 0;
                }
            }

            //load a image by opening a stream to the server
            SecureStream ImgStream = new SecureStream(this);
            int count = 0;
            Benchmark BenchFiles = new Benchmark();

            //Image img = (Image)Bitmap.FromStream(ImgStream);
            //img.Save(@"C:\Users\DragonHunter\Desktop\DownloadedSSP_Image.png");

            while (false)
            {
                Console.WriteLine("Synchronized Server Time: " + base.TimeSync.Hour.ToString("D2") + ":" + base.TimeSync.Minute.ToString("D2") + ":" + base.TimeSync.Second.ToString("D2") + ", " + base.TimeSync.Millisecond);
                Thread.Sleep(1000);
            }

            int packets = 0;
            ulong DataPerSec = 0;
            Stopwatch sw = Stopwatch.StartNew();
            Random rnd = new Random();
            TestMessage message = new TestMessage();
            int ChannelsClosed = 0;

            while(false)
            {
                TestChannel channel = new TestChannel();
                
                if (this.OpenChannel(channel) == ChannelError.Success)
                {
                    while (true)
                    {
                        channel.SendMessage(message);
                    }
                    channel.CloseChannel();
                    ChannelsClosed++;

                    if (sw.ElapsedMilliseconds >= 1000)
                    {
                        Console.WriteLine("channels opend/closed: " + ChannelsClosed);
                        sw = Stopwatch.StartNew();
                    }
                }
            }

            RandomDecimal rndDec = new RandomDecimal(DateTime.Now.Millisecond);

            while (base.Connected)
            {
                packets++;
                DataPerSec += (ulong)message.Stuff.Length;
                SharedTest.SendByteArray(message.Stuff);

                if (sw.ElapsedMilliseconds >= 1000)
                {
                    Console.WriteLine("last data size: " + message.Stuff.Length + ", pps:" + packets + ", data/sec:" + DataPerSec + " [" + Math.Round(((float)DataPerSec / 1000F) / 1000F, 2) + "MBps] " + (Math.Round((((float)DataPerSec / 1000F) / 1000F) / 1000F, 2) * 8F) + "Gbps");
                    packets = 0;
                    DataPerSec = 0;
                    sw = Stopwatch.StartNew();
                }
            }
            Process.GetCurrentProcess().WaitForExit();
        }

        public override void onDisconnect(DisconnectReason Reason)
        {
            Console.WriteLine("Disconnected from the server!");
            if (base.Certificate.ValidTo > base.TimeSync.Subtract(TimeSpan.FromSeconds(10))) //synchronized time might not be exactly correct
            {
                Console.WriteLine("The certificate time ended!");
            }
        }

        public override void onValidatingComplete()
        {
            Console.WriteLine("Validating connection...");
        }

        public override void onKeepAlive()
        {

        }

        public override void onException(Exception ex, ErrorType errorType)
        {
            Console.WriteLine(ex);
        }

        public override void onReconnect()
        {

        }

        public override void onNewChannelOpen(Channel channel)
        {

        }

        public override bool onVerifyCertificate(CertInfo certificate)
        {
            Console.WriteLine("Received certificate...");
            Console.WriteLine("Checksum: " + certificate.Checksum);
            Console.WriteLine("Cipher: " + certificate.Cipher);
            Console.WriteLine("CommonName: " + certificate.CommonName);
            Console.WriteLine("Compression: " + certificate.Compression);
            Console.WriteLine("Country: " + certificate.Country);
            Console.WriteLine("FingerPrintMd5: " + certificate.FingerPrintMd5);
            Console.WriteLine("FingerPrintSha1: " + certificate.FingerPrintSha1);
            Console.WriteLine("HandshakeMethod: " + certificate.HandshakeMethod);
            Console.WriteLine("IssuerCommonName: " + certificate.IssuerCommonName);
            Console.WriteLine("IssuerCountry: " + certificate.IssuerCountry);
            Console.WriteLine("IssuerOrganization: " + certificate.IssuerOrganization);
            Console.WriteLine("KeyAlgorithm: " + certificate.KeyAlgorithm);
            Console.WriteLine("Locality: " + certificate.Locality);
            Console.WriteLine("Organization: " + certificate.Organization);
            Console.WriteLine("State: " + certificate.State);
            Console.WriteLine("Unit: " + certificate.Unit);
            Console.WriteLine("ValidFrom: " + certificate.ValidFrom);
            Console.WriteLine("ValidTo: " + certificate.ValidTo);

            if (new CertForm(certificate.ImgCertificate).ShowDialog() != DialogResult.OK)
            {
                return false;
            }
            return true;
        }

        public override IPlugin[] onGetPlugins()
        {
            return new IPlugin[]
            {

            };
        }

        public override void onAddProtection(Protection protection)
        {
            protection.AddProtection(new QuickLzProtection());
        }

        public override uint HeaderJunkCount
        {
            get { return 5; }
        }

        public override uint PrivateKeyOffset
        {
            get { return 45634232; }
        }

        public override void onAuthenticated()
        {

        }

        public override void onNewStreamOpen(SecureStream stream)
        {

        }

        public override void onShareClasses()
        {

        }

        public override bool onPeerConnectionRequest(RootPeer peer)
        {
            Console.WriteLine("Allowed connect permission for peer " + peer.VirtualIP);
            return true;
        }

        public override RootPeer onGetNewPeerObject()
        {
            return new Peer();
        }
    }
}