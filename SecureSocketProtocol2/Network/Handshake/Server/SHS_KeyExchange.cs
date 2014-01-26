using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    internal class SHS_KeyExchange : Handshake
    {
        private ServerProperties serverProperties;
        private PrivateKeyHandler KeyHandler;

        public SHS_KeyExchange(SSPClient client, ServerProperties serverProperties, PrivateKeyHandler KeyHandler)
            : base(client)
        {
            this.serverProperties = serverProperties;
            this.KeyHandler = KeyHandler;
        }

        public override HandshakeType[] ServerTypes
        {
            get
            {
                return new HandshakeType[]
                {
                    HandshakeType.SendMessage,
                    HandshakeType.SendMessage,
                    HandshakeType.ReceiveMessage,
                };
            }
        }

        public override HandshakeType[] ClientTypes
        {
            get
            {
                return new HandshakeType[]
                {
                    HandshakeType.ReceiveMessage,
                    HandshakeType.ReceiveMessage,
                    HandshakeType.SendMessage,
                };
            }
        }

        public override bool onHandshake()
        {
            DiffieHellman diffieHellman = new DiffieHellman(256);

            //send RSA private key
            RSAEncryption RSA = KeyHandler.GetPrivateKey();
            base.SendMessage(new MsgRsaPublicKey(RSA.PrivateKey)); //<- private key

            //generate a big random key
            byte[] encryptionKey = new byte[65535];
            new Random(DateTime.Now.Millisecond).NextBytes(encryptionKey);

            //encrypt the key with RSA
            byte[] cryptedKey = RSA.Encrypt(encryptionKey, 0, encryptionKey.Length);
            uint KeyHash = BitConverter.ToUInt32(new CRC32().ComputeHash(cryptedKey), 0); //could be vulnerable, CRC32 reversing

            diffieHellman = KeyHandler.GetDiffieHellman();
            byte[] diffieStr = diffieHellman.GetDiffie();
            long index = Client.PrivateKeyOffset % cryptedKey.Length;
            if (index <= 4)
                index = 10;
            byte[] diffieLen = BitConverter.GetBytes(diffieStr.Length);

            //create a backup of encrypted RSA data
            byte[] RsaBackup = new byte[diffieLen.Length + diffieStr.Length];
            Array.Copy(cryptedKey, index - 4, RsaBackup, 0, RsaBackup.Length); //Rsa Backup Data
            Array.Copy(diffieLen, 0, cryptedKey, index - 4, diffieLen.Length); //write Diffie-Hellman key length
            Array.Copy(diffieStr, 0, cryptedKey, index, diffieStr.Length); //copy the diffie-hellman key in between random data

            //maybe not secure adding this at the end of the encrypted data but whatever for now
            Array.Resize(ref cryptedKey, cryptedKey.Length + RsaBackup.Length);
            Array.Copy(RsaBackup, 0, cryptedKey, cryptedKey.Length - RsaBackup.Length, RsaBackup.Length);


            CertInfo certificate = new CertInfo(serverProperties.ServerCertificate);
            certificate.FingerPrintMd5 = BitConverter.ToString(MD5.Create().ComputeHash(serverProperties.ServerCertificate.PrivateKey)).Replace("-", "");
            certificate.FingerPrintSha1 = BitConverter.ToString(SHA1.Create().ComputeHash(serverProperties.ServerCertificate.PrivateKey)).Replace("-", "");
            certificate.KeyAlgorithm = "RSA with " + Connection.RSA_KEY_SIZE + "bit";
            certificate.Compression = "";//serverProperties.Compression.ToString();
            certificate.Cipher = "";// serverProperties.Encryption.ToString();
            certificate.HandshakeMethod = "RSA" + Connection.RSA_KEY_SIZE + "-DiffieHellman-AES256";

            if (!serverProperties.ServerCertificate.ShowProtectionMethods)
            {
                certificate.Cipher = "";
                certificate.Checksum = ChecksumHash.None;
                certificate.Compression = "";
                certificate.HandshakeMethod = "";
                certificate.KeyAlgorithm = "";
            }

            Client.Certificate = certificate;

            //send encryption info + diffie-hellman
            base.SendMessage(new MsgServerEncryption(serverProperties.AllowUdp, certificate, cryptedKey, KeyHash));

            if (!base.ReceiveMessage((IMessage message) =>
            {
                MsgDiffiehellman diffie = message as MsgDiffiehellman;

                if (diffie != null)
                {
                    try
                    {
                        diffieHellman.HandleResponse(new PayloadReader(diffie.DiffieHellman));
                        Client.Connection.protection.ApplyPrivateKey(diffieHellman.Key); //apply salt-key
                        Client.Connection.protection.ApplyPrivateKey(encryptionKey); //apply secure key
                        return true;
                    }
                    catch { return false; }
                }
                return false;
            }).Wait<bool>(false, 30000))
            {
                Client.Disconnect();
                return false;
            }
            return true;
        }
    }
}
