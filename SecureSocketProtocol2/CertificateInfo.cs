using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace SecureSocketProtocol2
{
    public abstract class CertificateInfo
    {
        public abstract string CommonName { get; }
        public abstract string Country { get; }
        public abstract string State { get; }
        public abstract string Locality { get; }
        public string KeyAlgorithm { get; internal set; }
        public string FingerPrintMd5 { get; internal set; }
        public string FingerPrintSha1 { get; internal set; }
        public string Cipher { get; internal set; }
        public string Compression { get; internal set; }
        public abstract DateTime ValidTo { get; }
        public abstract DateTime ValidFrom { get; }
        public abstract string Organization { get; }
        public abstract string Unit { get; }
        public abstract string IssuerCommonName { get; }
        public abstract string IssuerOrganization { get; }
        public abstract string IssuerCountry { get; }
        public string HandshakeMethod { get; internal set; }
        public abstract bool ShowProtectionMethods { get; }
        public abstract ChecksumHash Checksum { get; }
        public abstract byte[] PrivateKey { get; }

        /// <summary>
        /// Initialize a new Certificate
        /// </summary>
        public CertificateInfo()
        {

        }
    }
}