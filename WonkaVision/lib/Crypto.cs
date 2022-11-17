using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO;

namespace WonkaVision.lib
{
    public class Crypto
    {
        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        public static byte[] KerberosChecksum(byte[] key, byte[] data, Interop.KERB_CHECKSUM_ALGORITHM cksumType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5, int keyUsage = (int)Interop.KERB_KEY_USAGE.KRB_NON_KERB_CKSUM_SALT)
        {
            Interop.KERB_CHECKSUM pCheckSum;
            IntPtr pCheckSumPtr;
            int status = Interop.CDLocateCheckSum(cksumType, out pCheckSumPtr);
            pCheckSum = (Interop.KERB_CHECKSUM)Marshal.PtrToStructure(pCheckSumPtr, typeof(Interop.KERB_CHECKSUM));
            if (status != 0)
            {
                throw new Win32Exception(status, "CDLocateCheckSum failed");
            }

            IntPtr Context;
            Interop.KERB_CHECKSUM_InitializeEx pCheckSumInitializeEx = (Interop.KERB_CHECKSUM_InitializeEx)Marshal.GetDelegateForFunctionPointer(pCheckSum.InitializeEx, typeof(Interop.KERB_CHECKSUM_InitializeEx));
            Interop.KERB_CHECKSUM_Sum pCheckSumSum = (Interop.KERB_CHECKSUM_Sum)Marshal.GetDelegateForFunctionPointer(pCheckSum.Sum, typeof(Interop.KERB_CHECKSUM_Sum));
            Interop.KERB_CHECKSUM_Finalize pCheckSumFinalize = (Interop.KERB_CHECKSUM_Finalize)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finalize, typeof(Interop.KERB_CHECKSUM_Finalize));
            Interop.KERB_CHECKSUM_Finish pCheckSumFinish = (Interop.KERB_CHECKSUM_Finish)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finish, typeof(Interop.KERB_CHECKSUM_Finish));

            // initialize the checksum
            // KERB_NON_KERB_CKSUM_SALT = 17
            int status2 = pCheckSumInitializeEx(key, key.Length, (int)keyUsage, out Context);
            if (status2 != 0)
                throw new Win32Exception(status2);

            // the output buffer for the checksum data
            byte[] checksumSrv = new byte[pCheckSum.Size];

            // actually checksum all the supplied data
            pCheckSumSum(Context, data.Length, data);

            // finish everything up
            pCheckSumFinalize(Context, checksumSrv);
            pCheckSumFinish(ref Context);

            return checksumSrv;
        }
        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosDecrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Decrypt pCSystemDecrypt = (Interop.KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Decrypt, typeof(Interop.KERB_ECRYPT_Decrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            // actually perform the decryption
            status = pCSystemDecrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output.Take(outputSize).ToArray();
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosEncrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Encrypt pCSystemEncrypt = (Interop.KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Encrypt, typeof(Interop.KERB_ECRYPT_Encrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            // actually perform the decryption
            status = pCSystemEncrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output;
        }

        public static Tuple<byte[], byte[]> CreateKeys()
        {
            byte[] publicBytes = null;
            byte[] privateBytes = null;

            try
            {
                CngKeyCreationParameters p = new CngKeyCreationParameters();
                p.ExportPolicy = CngExportPolicies.AllowPlaintextExport;
                p.KeyUsage = CngKeyUsages.KeyAgreement;

                CngKey k = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, null, p);

                publicBytes = k.Export(CngKeyBlobFormat.EccPublicBlob);
                privateBytes = k.Export(CngKeyBlobFormat.EccPrivateBlob);
            }
            catch
            {
                Helpers.WriteConsole("[X] Error: unable to create key file, try setting modify permissions to the user on the following directory:");
                Helpers.WriteConsole("C:\\ProgramData\\Application Data\\Microsoft\\Crypto\\Keys");
            }

            return Tuple.Create(publicBytes, privateBytes);
        }

        public static Tuple<byte[], byte[]> EncryptData(byte[] privateKey, byte[] publicKey, byte[] data)
        {
            byte[] encryptedData = null;
            byte[] iV = null;

            using (CngKey pk = CngKey.Import(privateKey, CngKeyBlobFormat.EccPrivateBlob))
            using (var myAlgorithm = new ECDiffieHellmanCng(pk))
            using (var pubKey = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                byte[] symmKey = myAlgorithm.DeriveKeyMaterial(pubKey);
                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.Key = symmKey;
                    aes.GenerateIV();

                    iV = aes.IV;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream ms = new MemoryStream())
                    {
                        var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
                        cs.Write(data, 0, data.Length);
                        cs.Close();
                        encryptedData = ms.ToArray();
                    }
                    aes.Clear();
                }
            }

            return Tuple.Create(iV, encryptedData);
        }

        public static byte[] DecryptData(byte[] privateKey, byte[] publicKey, byte[] iV,  byte[] data)
        {
            byte[] plainTextData = null;

            using (CngKey pk = CngKey.Import(privateKey, CngKeyBlobFormat.EccPrivateBlob))
            using (var myAlgorithm = new ECDiffieHellmanCng(pk))
            using (var pubKey = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                byte[] symmKey = myAlgorithm.DeriveKeyMaterial(pubKey);
                var aes = new AesCryptoServiceProvider();

                aes.Key = symmKey;
                aes.IV = iV;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write);
                    cs.Write(data, 0, data.Length);
                    cs.Close();

                    plainTextData = ms.ToArray();
                }
                aes.Clear();
            }
            return plainTextData;
        }
    }
}
