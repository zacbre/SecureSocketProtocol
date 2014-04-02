using System;
using System.Collections.Generic;
using System.Text;

/*
 * Credits to DragonHunter for Reverse Engineering
 * This encryption officialy came from a online MMORPG game
 * Reverse engineered / converted to C#
 */
#region Reversed Engineered code
/*
Engine.dll+171AB2 - CC                - int 3 
Engine.dll+171AB3 - CC                - int 3 
Engine.dll+171AB4 - CC                - int 3 
Engine.dll+171AB5 - CC                - int 3 
Engine.dll+171AB6 - CC                - int 3 
Engine.dll+171AB7 - CC                - int 3 
Engine.dll+171AB8 - CC                - int 3 
Engine.dll+171AB9 - CC                - int 3 
Engine.dll+171ABA - CC                - int 3 
Engine.dll+171ABB - CC                - int 3 
Engine.dll+171ABC - CC                - int 3 
Engine.dll+171ABD - CC                - int 3 
Engine.dll+171ABE - CC                - int 3 
Engine.dll+171ABF - CC                - int 3 
Engine.dll+171AC0 - 55                - push ebp
Engine.dll+171AC1 - 8B EC             - mov ebp,esp
Engine.dll+171AC3 - 57                - push edi
Engine.dll+171AC4 - 56                - push esi
Engine.dll+171AC5 - 8B 75 0C          - mov esi,[ebp+0C]
Engine.dll+171AC8 - 8B 4D 10          - mov ecx,[ebp+10]
Engine.dll+171ACB - 8B 7D 08          - mov edi,[ebp+08]
Engine.dll+171ACE - 8B C1             - mov eax,ecx
Engine.dll+171AD0 - 8B D1             - mov edx,ecx
Engine.dll+171AD2 - 03 C6             - add eax,esi
Engine.dll+171AD4 - 3B FE             - cmp edi,esi
Engine.dll+171AD6 - 76 08             - jna 20171AE0
Engine.dll+171AD8 - 3B F8             - cmp edi,eax
Engine.dll+171ADA - 0F82 A4010000     - jb 20171C84
Engine.dll+171AE0 - 81 F9 00010000    - cmp ecx,00000100
Engine.dll+171AE6 - 72 1F             - jb 20171B07
Engine.dll+171AE8 - 83 3D FCFC6C21 00 - cmp dword ptr [216CFCFC],00
Engine.dll+171AEF - 74 16             - je 20171B07
Engine.dll+171AF1 - 57                - push edi
Engine.dll+171AF2 - 56                - push esi
Engine.dll+171AF3 - 83 E7 0F          - and edi,0F
Engine.dll+171AF6 - 83 E6 0F          - and esi,0F
Engine.dll+171AF9 - 3B FE             - cmp edi,esi
Engine.dll+171AFB - 5E                - pop esi
Engine.dll+171AFC - 5F                - pop edi
Engine.dll+171AFD - 75 08             - jne 20171B07
Engine.dll+171AFF - 5E                - pop esi
Engine.dll+171B00 - 5F                - pop edi
Engine.dll+171B01 - 5D                - pop ebp
Engine.dll+171B02 - E9 89230100       - jmp 20183E90
Engine.dll+171B07 - F7 C7 03000000    - test edi,0003
Engine.dll+171B0D - 75 15             - jne 20171B24
Engine.dll+171B0F - C1 E9 02          - shr ecx,02
Engine.dll+171B12 - 83 E2 03          - and edx,03
Engine.dll+171B15 - 83 F9 08          - cmp ecx,08
Engine.dll+171B18 - 72 2A             - jb 20171B44
Engine.dll+171B1A - F3 A5             - repe movsd 
Engine.dll+171B1C - FF 24 95          - jmp dword ptr [edx*4]
Engine.dll+171B1F - 34 1C             - xor al,1C
Engine.dll+171B21 - 17                - pop ss
Engine.dll+171B22 - 20 90 8BC7BA03    - and [eax+03BAC78B],dl
Engine.dll+171B28 - 00 00             - add [eax],al
Engine.dll+171B2A - 00 83 E904720C    - add [ebx+0C7204E9],al
Engine.dll+171B30 - 83 E0 03          - and eax,03
Engine.dll+171B33 - 03 C8             - add ecx,eax
Engine.dll+171B35 - FF 24 85          - jmp dword ptr [eax*4]
Engine.dll+171B38 - 48                - dec eax
Engine.dll+171B39 - 1B 17             - sbb edx,[edi]
Engine.dll+171B3B - 20 FF             - and bh,bh
Engine.dll+171B3D - 24 8D             - and al,8D
Engine.dll+171B3F - 44                - inc esp
Engine.dll+171B40 - 1C 17             - sbb al,17
Engine.dll+171B42 - 20 90 FF248DC8    - and [eax-3772DB01],dl
Engine.dll+171B48 - 1B 17             - sbb edx,[edi]
Engine.dll+171B4A - 20 90 581B1720    - and [eax+20171B58],dl
Engine.dll+171B50 - 84 1B             - test [ebx],bl
Engine.dll+171B52 - 17                - pop ss
Engine.dll+171B53 - 20 A8 1B172023    - and [eax+2320171B],ch
Engine.dll+171B59 - D1 8A 0688078A    - ror [edx-75F877FA],1
Engine.dll+171B5F - 46                - inc esi
Engine.dll+171B60 - 01 88 47018A46    - add [eax+468A0147],ecx
Engine.dll+171B66 - 02 C1             - add al,cl
Engine.dll+171B68 - E9 02884702       - jmp 225EA36F
Engine.dll+171B6D - 83 C6 03          - add esi,03
Engine.dll+171B70 - 83 C7 03          - add edi,03
Engine.dll+171B73 - 83 F9 08          - cmp ecx,08
Engine.dll+171B76 - 72 CC             - jb 20171B44
Engine.dll+171B78 - F3 A5             - repe movsd 
Engine.dll+171B7A - FF 24 95          - jmp dword ptr [edx*4]
Engine.dll+171B7D - 34 1C             - xor al,1C
Engine.dll+171B7F - 17                - pop ss
Engine.dll+171B80 - 20 8D 490023D1    - and [ebp-2EDCFFB7],cl
Engine.dll+171B86 - 8A 06             - mov al,[esi]
Engine.dll+171B88 - 88 07             - mov [edi],al
Engine.dll+171B8A - 8A 46 01          - mov al,[esi+01]
Engine.dll+171B8D - C1 E9 02          - shr ecx,02
Engine.dll+171B90 - 88 47 01          - mov [edi+01],al
Engine.dll+171B93 - 83 C6 02          - add esi,02
Engine.dll+171B96 - 83 C7 02          - add edi,02
Engine.dll+171B99 - 83 F9 08          - cmp ecx,08
Engine.dll+171B9C - 72 A6             - jb 20171B44
Engine.dll+171B9E - F3 A5             - repe movsd 
Engine.dll+171BA0 - FF 24 95          - jmp dword ptr [edx*4]
Engine.dll+171BA3 - 34 1C             - xor al,1C
Engine.dll+171BA5 - 17                - pop ss
Engine.dll+171BA6 - 20 90 23D18A06    - and [eax+068AD123],dl
Engine.dll+171BAC - 88 07             - mov [edi],al
Engine.dll+171BAE - 83 C6 01          - add esi,01
Engine.dll+171BB1 - C1 E9 02          - shr ecx,02
Engine.dll+171BB4 - 83 C7 01          - add edi,01
Engine.dll+171BB7 - 83 F9 08          - cmp ecx,08
Engine.dll+171BBA - 72 88             - jb 20171B44
Engine.dll+171BBC - F3 A5             - repe movsd 
Engine.dll+171BBE - FF 24 95          - jmp dword ptr [edx*4]
Engine.dll+171BC1 - 34 1C             - xor al,1C
Engine.dll+171BC3 - 17                - pop ss
Engine.dll+171BC4 - 20 8D 49002B1C    - and [ebp+1C2B0049],cl
Engine.dll+171BCA - 17                - pop ss
Engine.dll+171BCB - 20 18             - and [eax],bl
Engine.dll+171BCD - 1C 17             - sbb al,17
Engine.dll+171BCF - 20 10             - and [eax],dl
Engine.dll+171BD1 - 1C 17             - sbb al,17
Engine.dll+171BD3 - 20 08             - and [eax],cl
Engine.dll+171BD5 - 1C 17             - sbb al,17
Engine.dll+171BD7 - 20 00             - and [eax],al
Engine.dll+171BD9 - 1C 17             - sbb al,17
Engine.dll+171BDB - 20 F8             - and al,bh
Engine.dll+171BDD - 1B 17             - sbb edx,[edi]
Engine.dll+171BDF - 20 F0             - and al,dh
Engine.dll+171BE1 - 1B 17             - sbb edx,[edi]
Engine.dll+171BE3 - 20 E8             - and al,ch
Engine.dll+171BE5 - 1B 17             - sbb edx,[edi]
Engine.dll+171BE7 - 20 8B 448EE489    - and [ebx-761B71BC],cl
Engine.dll+171BED - 44                - inc esp
Engine.dll+171BEE - 8F                - db 8f
Engine.dll+171BEF - E4 8B             - in al,8B
Engine.dll+171BF1 - 44                - inc esp
Engine.dll+171BF2 - 8E E8             - mov gs,ax
Engine.dll+171BF4 - 89 44 8F E8       - mov [edi+ecx*4-18],eax
Engine.dll+171BF8 - 8B 44 8E EC       - mov eax,[esi+ecx*4-14]
Engine.dll+171BFC - 89 44 8F EC       - mov [edi+ecx*4-14],eax
Engine.dll+171C00 - 8B 44 8E F0       - mov eax,[esi+ecx*4-10]
Engine.dll+171C04 - 89 44 8F F0       - mov [edi+ecx*4-10],eax
Engine.dll+171C08 - 8B 44 8E F4       - mov eax,[esi+ecx*4-0C]
Engine.dll+171C0C - 89 44 8F F4       - mov [edi+ecx*4-0C],eax
Engine.dll+171C10 - 8B 44 8E F8       - mov eax,[esi+ecx*4-08]
Engine.dll+171C14 - 89 44 8F F8       - mov [edi+ecx*4-08],eax
Engine.dll+171C18 - 8B 44 8E FC       - mov eax,[esi+ecx*4-04]
Engine.dll+171C1C - 89 44 8F FC       - mov [edi+ecx*4-04],eax
Engine.dll+171C20 - 8D 04 8D          - lea eax,[ecx*4]
Engine.dll+171C23 - 00 00             - add [eax],al
Engine.dll+171C25 - 00 00             - add [eax],al
Engine.dll+171C27 - 03 F0             - add esi,eax
Engine.dll+171C29 - 03 F8             - add edi,eax
Engine.dll+171C2B - FF 24 95          - jmp dword ptr [edx*4]
Engine.dll+171C2E - 34 1C             - xor al,1C
Engine.dll+171C30 - 17                - pop ss
Engine.dll+171C31 - 20 8B FF441C17    - and [ebx+171C44FF],cl
Engine.dll+171C37 - 20 4C 1C 17       - and [esp+ebx+17],cl
Engine.dll+171C3B - 20 58 1C          - and [eax+1C],bl
Engine.dll+171C3E - 17                - pop ss
Engine.dll+171C3F - 20 6C 1C 17       - and [esp+ebx+17],ch
Engine.dll+171C43 - 20 8B 45085E5F    - and [ebx+5F5E0845],cl
Engine.dll+171C49 - C9                - leave 
Engine.dll+171C4A - C3                - ret 
*/
#endregion

namespace SecureSocketProtocol2.Encryptions
{
    internal class PolyXor
    {
        private byte[] _inKey = new byte[16];
        private byte[] _outKey = new byte[16];
        private object ProcessLock = new object();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key">The key must be only 16bytes int length</param>
        public PolyXor(byte[] key)
        {
            if (key.Length != 16)
                throw new Exception("Key must be 16 bytes in length");

            Array.Copy(key, 0, _inKey, 0, 16);
            Array.Copy(key, 0, _outKey, 0, 16);
        }

        public byte[] Encrypt(byte[] data)
        {
            lock (ProcessLock)
            {
                int temp = 0;
                for (int i = 0; i < data.Length; i++)
                {
                    int temp2 = data[i] & 0xFF;
                    temp = temp2 ^ _outKey[i & 15] ^ temp;
                    data[i] = (byte)temp;
                }
                Array.Copy(BitConverter.GetBytes(BitConverter.ToInt32(_outKey, 8) + data.Length), 0, _outKey, 8, 4);
                return data;
            }
        }

        public byte[] Decrypt(byte[] data)
        {
            lock (ProcessLock)
            {
                int temp = 0;
                for (int i = 0; i < data.Length; i++)
                {
                    int temp2 = data[i] & 0xFF;
                    data[i] = (byte)(temp2 ^ _inKey[i & 15] ^ temp);
                    temp = temp2;
                }
                Array.Copy(BitConverter.GetBytes(BitConverter.ToInt32(_inKey, 8) + data.Length), 0, _inKey, 8, 4);
                return data;
            }
        }
    }
}
