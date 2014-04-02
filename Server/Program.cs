using SecureSocketProtocol2;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Server
{
    class Program : SSPServer
    {
        public static Program prog;

        public Program()
            : base(new ServerProps())
        {

        }

        static void Main(string[] args)
        {
            Console.Title = "SSP - SERVER";
            prog = new Program();
            Console.WriteLine("Listening at port 1337");
            Process.GetCurrentProcess().WaitForExit();
        }

        public override void onConnectionAccept(SSPClient client)
        {
            Console.WriteLine("Accepted client");
        }

        public override void onConnectionClosed(SSPClient client)
        {

        }

        public override void onException(Exception ex)
        {
            Console.WriteLine("Error occured: " + ex.StackTrace);
        }

        public override bool onAuthentication(SSPClient client, string Username, string Password)
        {
            Console.WriteLine("Authenication, Username:" + Username + ", Password:" + Password);

            if (Username == "Dergan" && Password == "1AF77DC7E7DDAB416977FA0CACE6840FBA7CA9D8FC580933DB74A8B58BED60F71B4E7FE85414E269E426E8C75A907EFB4021F2248FB9BEA5")
                return true;

            return false;
        }

        public override bool onPeerConnectionRequest(SSPClient FromClient, SSPClient ToClient)
        {
            Console.WriteLine("Permission granted for connecting from " + FromClient.VirtualIP + " to " + ToClient.VirtualIP);
            return true;
        }
        public override bool onPeerCreateDnsRequest(string DnsName, SSPClient Requestor)
        {
            return true;
        }
    }

    class ServerProps : ServerProperties
    {
        public ServerProps()
            : base()
        {

        }

        public override ushort ListenPort { get { return 444; } }
        public override string ListenIp { get { return "0.0.0.0"; } }
        public override bool AllowUdp { get { return true; } }
        public override bool UserPassAuthenication { get { return true; } }

        public override CertificateInfo ServerCertificate
        {
            get { return new Certificate(); }
        }

        public override Stream[] KeyFiles
        {
            get
            {
                return new Stream[]
                {
                    //new FileStream(@"C:\Users\Anguis\Desktop\lel.png", FileMode.Open, FileAccess.Read, FileShare.Read)
                };
            }
        }

        public override bool GenerateKeysInBackground
        {
            get { return false; }
        }

        public override SSPClient GetNewClient()
        {
            return new Client();
        }
    }

    public class Certificate : CertificateInfo
    {
        private DateTime CreatedAt;

        public override string CommonName
        {
            get { return "Secure Socket Protocol"; }
        }

        public override string Country
        {
            get { return "The Netherlands"; }
        }

        public override string State
        {
            get { return "Unknown"; }
        }

        public override string Locality
        {
            get { return "Unknown"; }
        }

        public override DateTime ValidTo
        {
            get { return this.CreatedAt.AddMinutes(15); }
        }

        public override DateTime ValidFrom
        {
            get { return this.CreatedAt; }
        }

        public override string Organization
        {
            get { return "DragonHunter's Cave"; }
        }

        public override string Unit
        {
            get { return "Unknown"; }
        }

        public override string IssuerCommonName
        {
            get { return "Unknown"; }
        }

        public override string IssuerOrganization
        {
            get { return "Unknown"; }
        }

        public override string IssuerCountry
        {
            get { return "Unknown"; }
        }

        public override bool ShowProtectionMethods
        {
            get { return false; }
        }

        public override ChecksumHash Checksum
        {
            get { return ChecksumHash.None; }
        }

        public override byte[] PrivateKey
        {
            get
            {
                return new byte[]
                {
                    80, 118, 131, 114, 195, 224, 157, 246, 141, 113,
                    186, 243, 77, 151, 247, 84, 70, 172, 112, 115,
                    112, 110, 91, 212, 159, 147, 180, 188, 143, 251,
                    218, 155
                };
            }
        }

        public Certificate()
            : base()
        {
            this.CreatedAt = DateTime.Now;
        }
    }
}