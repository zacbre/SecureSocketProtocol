using SecureSocketProtocol2.Hashers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2.Network.RootSocket
{
    public class RootDns
    {
        internal SortedList<uint, RootDnsInfo> DnsNames { get; private set; }
        private Random random;

        public RootDns()
        {
            random = new Random(DateTime.Now.Millisecond);
            DnsNames = new SortedList<uint, RootDnsInfo>();
        }

        public void ReadDnsFile(string FilePath)
        {
            DnsNames.Clear();
            if (File.Exists(FilePath) && new FileInfo(FilePath).Length > 0)
            {
                PayloadReader pr = new PayloadReader(File.ReadAllBytes(FilePath));

                for (int i = 0; pr.Offset < pr.Length; i++)
                {
                    string name = pr.ReadString();
                    uint DnsId = pr.ReadUInteger();
                    DnsNames.Add(DnsId, new RootDnsInfo(name, DnsId));
                }
            }
        }

        public void WriteDnsFile(string FilePath)
        {
            if (!File.Exists(FilePath))
                File.Create(FilePath).Close();

            PayloadWriter pw = new PayloadWriter();
            for (int i = 0; i < DnsNames.Count; i++)
            {
                pw.WriteString(DnsNames.Values[i].DnsName);
                pw.WriteUInteger(DnsNames.Values[i].DnsId);
            }
            File.WriteAllBytes(FilePath, pw.ToByteArray());
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="name"></param>
        /// <param name="DnsId">Only the owner of the DNS must have this to update his IP address</param>
        /// <returns></returns>
        public bool ApplyDnsName(string name, ref uint DnsId, SSPClient peer)
        {
            name = name.ToLower();
            DnsId = new MurmurHash2UInt32Hack().Hash(ASCIIEncoding.Unicode.GetBytes(name));
            for (int i = 0; i < DnsNames.Count; i++)
            {
                if (DnsNames.Values[i].DnsId == DnsId)
                    return false;
            }

            RootDnsInfo dns = new RootDnsInfo(name, DnsId);
            dns.VirtualIp = peer.VirtualIP;
            DnsNames.Add(DnsId, dns);
            return true;
        }

        public RootDnsInfo GetDnsRecord(string name)
        {
            name = name.ToLower();
            uint DnsId = new MurmurHash2UInt32Hack().Hash(ASCIIEncoding.Unicode.GetBytes(name));

            RootDnsInfo record = null;
            DnsNames.TryGetValue(DnsId, out record);
            return record;
        }
    }
}