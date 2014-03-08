using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Protections.Cache;
using SecureSocketProtocol2.Network.Protections.Compression;
using SecureSocketProtocol2.Network.Protections.Encryption;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections
{
    public class Protection
    {
        public bool UsingPrivateKey { get; private set; }
        private SortedList<ProtectionType, List<IProtection>> Protections;
        private Connection connection;

        public int LayerCount
        {
            get
            {
                return CompressionCount + CacheCount + EncryptionCount;
            }
        }
        public int CompressionCount
        {
            get
            {
                if(Protections.ContainsKey(ProtectionType.Compression))
                    return Protections[ProtectionType.Compression].Count;
                return 0;
            }
        }
        public int CacheCount
        {
            get
            {

                if (Protections.ContainsKey(ProtectionType.Cache))
                    return Protections[ProtectionType.Cache].Count;
                return 0;
            }
        }
        public int EncryptionCount
        {
            get
            {
                if (Protections.ContainsKey(ProtectionType.Encryption))
                    return Protections[ProtectionType.Encryption].Count;
                return 0;
            }
        }

        public Protection(Connection connection)
        {
            this.connection = connection;
            this.Protections = new SortedList<ProtectionType, List<IProtection>>();
        }

        /// <summary>
        /// Add a protection to use with this connection, you can add Encryptions, Compressions and more as a extra layer of security
        /// </summary>
        /// <param name="protection">The protection to add</param>
        public void AddProtection(IProtection protection)
        {
            lock (connection.Client)
            {
                if (protection == null)
                    return;

                protection.Enabled = true;

                if (!this.Protections.ContainsKey(protection.Type))
                    this.Protections.Add(protection.Type, new List<IProtection>());
                this.Protections[protection.Type].Add(protection);
            }
        }

        internal byte[] ApplyProtection(byte[] Data, ref uint Offset, ref uint Length, ref PacketHeader header)
        {
            ApplyProtection(ref Data, ref Offset, ref Length, ref header, ProtectionType.Cache);
            ApplyProtection(ref Data, ref Offset, ref Length, ref header, ProtectionType.Compression);
            ApplyProtection(ref Data, ref Offset, ref Length, ref header, ProtectionType.Encryption);
            return Data;
        }

        internal byte[] RemoveProtection(byte[] Data, ref uint Offset, ref uint Length, ref PacketHeader header)
        {
            RemoveProtection(ref Data, ref Offset, ref Length, ref header, ProtectionType.Encryption);

            if (header.isCompressed)
            {
                RemoveProtection(ref Data, ref Offset, ref Length, ref header, ProtectionType.Compression);
            }
            if (header.isCached)
            {
                RemoveProtection(ref Data, ref Offset, ref Length, ref header, ProtectionType.Cache);
            }
            return Data;
        }

        private void ApplyProtection(ref byte[] Data, ref uint Offset, ref uint Length, ref PacketHeader header, ProtectionType Type)
        {
            if (Protections.ContainsKey(Type))
            {
                foreach (IProtection protection in Protections[Type])
                {
                    if (protection.Enabled)
                    {
                        Data = protection.Encode(ref Data, ref Offset, ref Length, ref header);
                    }
                }
            }
        }

        private void RemoveProtection(ref byte[] Data, ref uint Offset, ref uint Length, ref PacketHeader header, ProtectionType Type)
        {
            if (Protections.ContainsKey(Type))
            {
                List<IProtection> protections = Protections[Type];
                for (int i = protections.Count - 1; i >= 0; i--)
                {
                    IProtection protection = protections[i];
                    if (protection.Enabled)
                        Data = protection.Decode(ref Data, ref Offset, ref Length, ref header);
                }
            }
        }

        /// <summary>
        /// Apply a private key to the encryption algorithm, you can add so many private keys as you wish
        /// </summary>
        /// <param name="privateKey">The private key</param>
        public void ApplyPrivateKey(byte[] privateKey)
        {
            lock (connection.Client)
            {
                if (Protections.ContainsKey(ProtectionType.Encryption))
                {
                    foreach (IProtection protection in Protections[ProtectionType.Encryption])
                    {
                        if (protection.Enabled)
                        {
                            protection.onApplyPrivateKey(privateKey);
                        }
                    }
                }
            }
            this.UsingPrivateKey = true;
        }
    }
}