using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Network;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
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

        private Bitmap _certImage = null;

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

        /// <summary>
        /// A unique generated image by using the private certificate fingerprint
        /// </summary>
        public Bitmap ImgCertificate
        {
            get
            {
                if (_certImage != null)
                    return _certImage;


                const int DataLength = 225;
                const int Size = 15;
                const int PixelSize = 5;
                byte[] PrivateData = new byte[0];
                Color uniqueColor = Color.FromArgb(255, 0, 0);

                using (PayloadWriter pw = new PayloadWriter())
                {
                    pw.WriteString(CommonName);
                    pw.WriteString(Country);
                    pw.WriteString(State);
                    pw.WriteString(Locality);
                    pw.WriteString(KeyAlgorithm);
                    pw.WriteString(FingerPrintMd5);
                    pw.WriteString(FingerPrintSha1);
                    pw.WriteString(Cipher);
                    pw.WriteString(Compression);
                    pw.WriteString(Organization);

                    int seed = pw.Length;
                    Random rnd = new Random(seed);

                    for (int i = seed; i < DataLength; i++)
                    {
                        pw.WriteByte((byte)rnd.Next(0, 256));
                    }

                    //make it unique
                    byte[] temp = pw.ToByteArray();

                    for (int x = 0; x < 2; x++)
                    {
                        for (int i = x; i < temp.Length; i++)
                        {
                            for (int j = 0; j < temp.Length; j++)
                            {
                                temp[j] ^= temp[i];
                            }
                        }
                    }
                    PrivateData = SHA512.Create().ComputeHash(temp);
                }

                using (PayloadWriter pw = new PayloadWriter())
                {
                    MurmurHash2UInt32Hack hasher = new MurmurHash2UInt32Hack();
                    for(int i = 0; i < PrivateData.Length; i += 4)
                    {
                        byte[] tempData = new byte[4];
                        Array.Copy(PrivateData, i, tempData, 0, tempData.Length);
                        pw.WriteUInteger(hasher.Hash(tempData));
                        uniqueColor = Color.FromArgb(tempData[0], tempData[2], tempData[3]);
                    }
                    PrivateData = pw.ToByteArray();
                }


                Bitmap img = new Bitmap(Size * PixelSize, Size * PixelSize);

                DataShuffler shuffler = new DataShuffler(734284823);
                //PrivateData = shuffler.Shuffle<byte>(

                using (Graphics g = Graphics.FromImage(img))
                {
                    g.CompositingQuality = System.Drawing.Drawing2D.CompositingQuality.HighQuality;
                    g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.HighQuality;
                    g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.NearestNeighbor;

                    bool DrawWhite = false;
                    int i = 0;
                    for (int y = 0; y < img.Height; y += PixelSize)
                    {
                        for (int x = 0; x < img.Width; x += PixelSize)
                        {
                            DrawWhite = PrivateData[i % PrivateData.Length] < 150;

                            for (int j = 0; j < PixelSize; j++)
                            {
                                g.DrawLine(new Pen(DrawWhite ? Color.FromArgb(255, 255, 255) : uniqueColor), x, y + j, x + PixelSize, y + j);
                            }
                            DrawWhite = !DrawWhite;
                            i++;
                        }
                    }
                }
                _certImage = img;
                return _certImage;
            }
        }
    }
}