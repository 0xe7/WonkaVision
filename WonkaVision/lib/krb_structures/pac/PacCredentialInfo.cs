using System;
using System.IO;
using WonkaVision.lib;
using WonkaVision.Ndr.Marshal;
using WonkaVision.Ndr;

namespace WonkaVision.Kerberos.PAC {
    class PacCredentialInfo : PacInfoBuffer {

        public int Version { get; set; }

        public Interop.KERB_ETYPE EncryptionType { get; set; }

        public _PAC_CREDENTIAL_DATA? CredentialInfo { get; set; }

        new byte[] key;

        public PacCredentialInfo(byte[] data, PacInfoBufferType type, byte[] key) :  base(data, type) {
            this.key = key;
            Decode(data);
        }

        public override byte[] Encode() {

            BinaryWriter bw = new BinaryWriter(new MemoryStream());

            bw.Write(Version);
            bw.Write((int)EncryptionType);

            _Marshal_Helper mh = new _Marshal_Helper();
            mh.WriteReferent(CredentialInfo, new Action<_PAC_CREDENTIAL_DATA>(mh.WriteStruct));
            byte[] plainText = mh.ToPickledType().ToArray();
            var encData = Crypto.KerberosEncrypt(EncryptionType, (int)Interop.KERB_KEY_USAGE.KRB_NON_KERB_SALT, key, plainText);
            bw.Write(encData);

            long alignment = ((bw.BaseStream.Position + 7) / 8) * 8;
            bw.BaseStream.SetLength(alignment);

            return ((MemoryStream)bw.BaseStream).ToArray();
        }

        protected override void Decode(byte[] data) {
            Version = br.ReadInt32();
            EncryptionType = (Interop.KERB_ETYPE)br.ReadInt32();

            if(key == null) {
                return;
            }

            var encCredData = br.ReadBytes((int)(br.BaseStream.Length - br.BaseStream.Position));
            var plainCredData = Crypto.KerberosDecrypt(EncryptionType, (int)Interop.KERB_KEY_USAGE.KRB_NON_KERB_SALT, key, encCredData);

            NdrPickledType npt = new NdrPickledType(plainCredData);
            _Unmarshal_Helper uh = new _Unmarshal_Helper(npt.Data);
            CredentialInfo = uh.ReadReferentValue(uh.ReadStruct<_PAC_CREDENTIAL_DATA>,false);           
        }
    }
}
