﻿using System;
using Asn1;
using System.Text;

namespace WonkaVision.lib.krb
{
    public class Ticket
    {
        //Ticket::= [APPLICATION 1] SEQUENCE {
        //        tkt-vno[0] INTEGER(5),
        //        realm[1] Realm,
        //        sname[2] PrincipalName,
        //        enc-part[3] EncryptedData -- EncTicketPart
        //}

        public Ticket(string domain, string service)
        {
            tkt_vno = 5;

            realm = domain;

            sname = new PrincipalName();
            sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            foreach (string part in service.Split('/'))
            {
                sname.name_string.Add(part);
            }
        }

        public Ticket(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        tkt_vno = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        realm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 2:
                        sname = new PrincipalName(s.Sub[0]);
                        break;
                    case 3:
                        enc_part = new EncryptedData(s.Sub[0]);
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // tkt-vno         [0] INTEGER (5)
            AsnElt tkt_vnoAsn = AsnElt.MakeInteger(tkt_vno);
            AsnElt tkt_vnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { tkt_vnoAsn });
            tkt_vnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, tkt_vnoSeq);


            // realm           [1] Realm
            AsnElt realmAsn = AsnElt.MakeString(AsnElt.IA5String, realm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            AsnElt realmAsnSeq = AsnElt.Make(AsnElt.SEQUENCE, realmAsn);
            realmAsnSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, realmAsnSeq);


            // sname           [2] PrincipalName
            AsnElt snameAsn = sname.Encode();
            snameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, snameAsn);


            // enc-part        [3] EncryptedData -- EncTicketPart
            AsnElt enc_partAsn = enc_part.Encode();
            AsnElt enc_partSeq = AsnElt.Make(AsnElt.SEQUENCE, enc_partAsn);
            enc_partSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, enc_partSeq);


            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { tkt_vnoSeq, realmAsnSeq, snameAsn, enc_partSeq });
            AsnElt totalSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { totalSeq });
            totalSeq2 = AsnElt.MakeImplicit(AsnElt.APPLICATION, 1, totalSeq2);

            return totalSeq2;
        }

        public EncTicketPart Decrypt(byte[] serviceKey, byte[] asrepKey, bool noAdData = false) {
            var decryptedTicket = Crypto.KerberosDecrypt((Interop.KERB_ETYPE)enc_part.etype, (int)Interop.KERB_KEY_USAGE.AS_REP_TGS_REP, serviceKey, enc_part.cipher);
            var encTicket = AsnElt.Decode(decryptedTicket, false);
            return  new EncTicketPart(encTicket.Sub[0], asrepKey, noAdData);
        }

        public int tkt_vno { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        public EncryptedData enc_part { get; set; }
    }
}