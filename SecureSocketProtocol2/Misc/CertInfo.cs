using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    /// <summary>
    /// Certificate Information
    /// </summary>
    [Serializable]
    public class CertInfo
    {
        public string CommonName { get; internal set; }
        public string Country { get; internal set; }
        public string State { get; internal set; }
        public string Locality { get; internal set; }
        public string KeyAlgorithm { get; internal set; }
        public string FingerPrintMd5 { get; internal set; }
        public string FingerPrintSha1 { get; internal set; }
        public string Cipher { get; internal set; }
        public string Compression { get; internal set; }
        public DateTime ValidTo { get; internal set; }
        public DateTime ValidFrom { get; internal set; }
        public string Organization { get; internal set; }
        public string Unit { get; internal set; }
        public string IssuerCommonName { get; internal set; }
        public string IssuerOrganization { get; internal set; }
        public string IssuerCountry { get; internal set; }
        public string HandshakeMethod { get; internal set; }
        public ChecksumHash Checksum { get; internal set; }

        /// <summary>
        /// Initialize a new Certificate
        /// </summary>
        public CertInfo(CertificateInfo info)
        {
            this.CommonName = info.CommonName;
            this.Country = info.Country;
            this.State = info.State;
            this.Locality = info.Locality;
            this.KeyAlgorithm = info.KeyAlgorithm;
            this.FingerPrintMd5 = info.FingerPrintMd5;
            this.FingerPrintSha1 = info.FingerPrintSha1;
            this.Cipher = info.Cipher;
            this.Compression = info.Compression;
            this.ValidTo = info.ValidTo;
            this.ValidFrom = info.ValidFrom;
            this.Organization = info.Organization;
            this.Unit = info.Unit;
            this.IssuerCommonName = info.IssuerCommonName;
            this.IssuerOrganization = info.IssuerOrganization;
            this.IssuerCountry = info.IssuerCountry;
            this.HandshakeMethod = info.HandshakeMethod;
            this.Checksum = info.Checksum;
        }
    }
}