using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network
{
    internal class PrivateKeyHandler
    {
        public const int Max_Private_Keys = 1000;
        public const int Min_Private_Keys = 100; //if less then xx amount of private keys are available generate new keys

        private List<RSAEncryption> PrivateKeys;
        private List<DiffieHellman> DiffieHellmans;

        private Thread GenThread;
        private Random rnd;
        private object GenLock = new object();

        public PrivateKeyHandler()
        {
            this.PrivateKeys = new List<RSAEncryption>();
            this.DiffieHellmans = new List<DiffieHellman>();
            this.rnd = new Random(DateTime.Now.Millisecond);
        }

        public RSAEncryption GetPrivateKey()
        {
            if (PrivateKeys.Count == 0)
            {
                if (GenThread == null)
                {
                    GenThread = new Thread(new ThreadStart(GenerateThread));
                    GenThread.Start();
                }
                return GenerateRsaKey();
            }
            else
            {
                lock (PrivateKeys)
                {
                    //get a random key
                    int index = rnd.Next(0, PrivateKeys.Count - 1);
                    RSAEncryption RSA = PrivateKeys[index];
                    PrivateKeys.RemoveAt(index);

                    if (PrivateKeys.Count < Min_Private_Keys && GenThread == null)
                    {
                        GenThread = new Thread(new ThreadStart(GenerateThread));
                        GenThread.Start();
                    }
                    return RSA;
                }
            }
        }

        public DiffieHellman GetDiffieHellman()
        {
            
            if (DiffieHellmans.Count == 0)
            {
                if (GenThread == null)
                {
                    GenThread = new Thread(new ThreadStart(GenerateThread));
                    GenThread.Start();
                }
                return GenerateDiffieHellman();
            }
            else
            {
                lock (DiffieHellmans)
                {
                    //get a random key
                    int index = rnd.Next(0, DiffieHellmans.Count - 1);
                    DiffieHellman diffie = DiffieHellmans[index];
                    DiffieHellmans.RemoveAt(index);

                    if (DiffieHellmans.Count < Min_Private_Keys && GenThread == null)
                    {
                        GenThread = new Thread(new ThreadStart(GenerateThread));
                        GenThread.Start();
                    }
                    return diffie;
                }
            }
        }

        private void GenerateThread()
        {
            while (PrivateKeys.Count < Max_Private_Keys || DiffieHellmans.Count < Max_Private_Keys)
            {
                if (PrivateKeys.Count < Max_Private_Keys)
                {
                    RSAEncryption RSA = GenerateRsaKey();
                    lock (PrivateKeys)
                    {
                        PrivateKeys.Add(RSA);
                    }
                }
                if (DiffieHellmans.Count < Max_Private_Keys)
                {
                    DiffieHellman diffie = GenerateDiffieHellman();
                    lock (DiffieHellmans)
                    {
                        DiffieHellmans.Add(diffie);
                    }
                }
            }
            GenThread = null;
        }

        private RSAEncryption GenerateRsaKey()
        {
            RSAEncryption RSA = new RSAEncryption(Connection.RSA_KEY_SIZE, true);
            RSA.GeneratePrivateKey();
            RSA.GeneratePublicKey();
            return RSA;
        }
        private DiffieHellman GenerateDiffieHellman()
        {
            DiffieHellman diffie = new DiffieHellman(256);
            diffie.GenerateRequest();
            return diffie;
        }
    }
}