using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using SecureSocketProtocol2.Network.Protections.Encryption;
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

            //send RSA public key
            RSAEncryption RSA = KeyHandler.GetPrivateKey();
            base.SendMessage(new MsgRsaPublicKey(RSA.Parameters));

            //Calculate and apply the public key as key
            //If the key is spoofed the next packet that's being send could fail if public key is generated wrong :)
            byte[] SecretHash = SHS_KeyExchange.CalculateSecretHash(RSA.Parameters.Modulus, RSA.Parameters.Exponent);
            Client.Connection.protection.ApplyPrivateKey(SecretHash);//apply our secret hash based on the public key

            //generate a big random key
            byte[] encryptionKey = new byte[65535];
            new Random(DateTime.Now.Millisecond).NextBytes(encryptionKey);

            //encrypt the key with RSA
            byte[] cryptedKey = RSA.Encrypt(encryptionKey, 0, encryptionKey.Length);

            diffieHellman = KeyHandler.GetDiffieHellman();

            byte[] diffieStr = diffieHellman.GetDiffie();
            long index = Client.PrivateKeyOffset % 65535;
            if (index <= 4)
                index = 10;

            byte[] diffieLen = BitConverter.GetBytes(diffieStr.Length);

            //create a backup of encrypted RSA data
            //byte[] RsaBackup = new byte[diffieLen.Length + diffieStr.Length];
            //Array.Copy(cryptedKey, index - 4, RsaBackup, 0, RsaBackup.Length); //Rsa Backup Data
            Array.Copy(diffieLen, 0, cryptedKey, index - 4, diffieLen.Length); //write Diffie-Hellman key length
            Array.Copy(diffieStr, 0, cryptedKey, index, diffieStr.Length); //copy the diffie-hellman key in between random data

            //maybe not secure adding this at the end of the encrypted data but whatever for now
            //Array.Resize(ref cryptedKey, cryptedKey.Length + RsaBackup.Length);
            //Array.Copy(RsaBackup, 0, cryptedKey, cryptedKey.Length - RsaBackup.Length, RsaBackup.Length);



            uint KeyHash = BitConverter.ToUInt32(new CRC32().ComputeHash(cryptedKey), 0);

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
                certificate.Compression = "";
                certificate.HandshakeMethod = "";
                certificate.KeyAlgorithm = "";
            }

            Client.Certificate = certificate;

            
            //Convert bytes to UINT
            uint[] TempKey = new uint[SecretHash.Length];
            for(int i = 0; i < TempKey.Length; i++)
                TempKey[i] = SecretHash[i];

            //Encrypt the diffie-hellman key with our SecretHash which is generated by our Public RSA
            UnsafeXor XorEncryption = new UnsafeXor(TempKey, true);
            XorEncryption.Encrypt(ref cryptedKey, 0, cryptedKey.Length);


            //send encryption info + diffie-hellman
            base.SendMessage(new MsgServerEncryption(serverProperties.AllowUdp, certificate, cryptedKey, KeyHash));

            //apply the Encrypted Key, Yes the Encrypted Key, if spoofed the key should change at the client side ;)
            Client.Connection.protection.ApplyPrivateKey(cryptedKey);

            if (!base.ReceiveMessage((IMessage message) =>
            {
                MsgDiffiehellman diffie = message as MsgDiffiehellman;

                if (diffie != null)
                {
                    try
                    {
                        diffieHellman.HandleResponse(new PayloadReader(diffie.DiffieHellman));
                        Client.Connection.protection.ApplyPrivateKey(diffieHellman.Key); //apply diffie-hellman key
                        return true;
                    }
                    catch { return false; }
                }
                return false;
            }).Wait<bool>(false, 30000))
            {
                Client.Disconnect(DisconnectReason.TimeOut);
                Client.onException(new Exception("Handshake went wrong, SHS_KeyExchange"), ErrorType.Core);
                return false;
            }
            return true;
        }

        private static object CalculationLock = new object();
        internal static byte[] CalculateSecretHash(byte[] Modulus, byte[] Exponent)
        {
            lock (CalculationLock)
            {
                SortedList<byte, int> NumCounter = new SortedList<byte, int>();
                for (int i = 0; i < Modulus.Length; i++)
                {
                    if (!NumCounter.ContainsKey(Modulus[i]))
                        NumCounter.Add(Modulus[i], 1);
                    else
                        NumCounter[Modulus[i]] = (NumCounter[Modulus[i]] + 1) * ((Exponent[i % Exponent.Length] + 3));
                }

                PayloadWriter pw = new PayloadWriter();
                for (int i = 0; i < NumCounter.Count; i++)
                {
                    long val = NumCounter.Keys[i] + (Modulus[(i * 3) % Modulus.Length] ^ (NumCounter.Keys[i] + NumCounter.Values[i]));
                    pw.WriteDouble(Math.Pow(val, 8));
                }

                SHA512Managed ShaHasher = new SHA512Managed();
                return ShaHasher.ComputeHash(pw.ToByteArray());
            }
        }
    }
}