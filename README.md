SecureSocketProtocol
====================

A network library designed to be secure.

[Features]
Secure connection which is hard to spoof
A private key which is never being send over the Internet
KeyFile support, use files as a extra encryption key like in TrueCrypt
Authentication support by Username and Password, The password is Hashed 11x by SHA-512 and MD5
Header Trash - Add useless junk to the header to make it more difficult to get to the payload
Plugin support


Certificate support:
CommonName, Country, State, Locality, ValidTo, ValidFrom
Organization, Unit, IssuerCommonName, IssuerOrganization
IssuerCountry, ShowProtectionMethods, Checksum, PrivateKey

The ValidTo is very important to understand what it does:
The ValidTo is meant to be used to show the client for how long he can stay conncted
If you take the current time and add 5 minutes to it the client can only stay for 5 minutes
If the time runs out the client will disconnect his self or the server will kick him

The PrivateKey in the certificate is being used as a private key, this key is never being send over the internet
The size of the key does not matter, if you want to feel secure take a 100MB (MegaByte) File and use that as private key
You can use a 100MB private key but keep this in mind (ClientsConnected x PrivateKeySize)

The Private Key Offset in the client/server is being used for Diffie-Hellman/RSA security
The server will generate a 65KB byte array in memory and with the PrivateKeyOffset you will tell where the private key of Diffie-Hellman will be stored
This will make it a lot harder to understand where the private diffie-hellman key is in the data

More information soon...
