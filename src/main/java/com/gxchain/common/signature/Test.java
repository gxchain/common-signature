package com.gxchain.common.signature;

import com.google.common.base.Preconditions;
import com.gxchain.common.signature.utils.*;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.ECKey.ECDSASignature;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

/**
 * Created by DOmmy on 2018/1/30.
 */
public class Test {
    private static final Logger LOGGER = LoggerFactory.getLogger(Test.class);

    private final String pubKey = "GXC6xkbvGfroQ32vkgApBuNKKJdEodDQh2wgPNHbNhxmvwhtdC9yT";
    private final String priKey = "5KJWEQRwXj1sojQTTurpmbt1tJh1mzwxCJxDhMmtYmP9TJsGMJ5";
    private static final String lanPriKey = "5Ka9YjFQtfUUX2DdnqkaPWH1rVeSeby7Cj2VdjRt79S9kKLvXR7";
    private static final String lanPubKey = "GXC7XzFVivuBtuc2rz3Efkb41JCN4KH7iENAx9rch9QkowEmc4UvV";
    private static final String lanSign =
            "1f74974acbb268fa573a941e8845a2efd6dc2222b2bfac248e7d70cebbb3eaa9ec0b7b470ca90794a2d2fbb72274e05142ff15b985d960d51e00fca9cb0dce2482";

    private final String priKey2 = "5KUXLgzt7LcYd4JJz3zPXCL3WX3DBWK4bQ2es8U3uyXBr5mQtsA";

    public void test() throws MalformedAddressException {
        String sig =
                "207841019ebf7668dab5be019bc652b8dae8e0d7fd997f963d1183bbccab4165ce1050cdaa68747d4d08a8abf492cadd6820f15b91373ba3609a4536b252993c70";
        String data = "{\"account\":\"init3\"}";
        String pub = "GXC5Yu6M75wt1HP87wpqqPrrNDANFMkgvA9djiT8N73D6Rq7zNraQ";

        byte[] sigBtyes = Util.hexToBytes(sig);
        // sigBtyes = ByteUtils.subArray(sigBtyes, 1);

        BigInteger r = new BigInteger(ByteUtils.subArray(sigBtyes, 1, 33));
        BigInteger s = new BigInteger(ByteUtils.subArray(sigBtyes, 33));
        LOGGER.info("r:" + r + ",s:" + s);
        // SignatureECDSASHA256
        ECDSASignature signature = new ECDSASignature(r, s);
        Address from = new Address(pub);
        PublicKey pk1 = from.getPublicKey();
        byte[] hash = Sha256Hash.hash(data.getBytes());
        LOGGER.info(""+pk1.getKey().verify(hash, signature.encodeToDER()));
    }

    public static void main(String[] args) {

//        String msg = "alskdnfalng";
//        String s =
//                MsgCryptUtil.encrypt("5J7yBwuhQR7GT6inztapkBX7BG55cDpVVdENyquNrgVjFgMrEvH", "GXC6pwfYuNec5frtYEBeCdiPsVTStJ1KKdRbh9iamBVrCZgRrZkKX", msg);
//        LOGGER.info(s);
//        LOGGER.info(MsgCryptUtil.decrypt("5K4s1eAemttjkqjKH8MsFWksNUwtjrvhNMWAwfR4ZbWnLr9e2Jq", "GXC8LctBof1AUqGLonPg8ZwXX3wSEhoCXGaSfGP1Lqgx6FFuaMPNm", s));
//
//        Test t = new Test();
//        //        t.test();
//        //        t.sign("123");
//        t.loop();
        //        t.loopData();

    }

    private void loopData() {
        String data = "123";
        for (int i = 0; i < 10000; i++) {
            sign(data);
            data += "!@#$%^&*() ,./<>'?:";
        }
    }

    private void loop() {
        String data = "123";
        int n = 0;
        for (int i = 0; i < 10000; i++) {
            long start = System.currentTimeMillis();
            String sign = SignatureUtil.signature(data, lanPriKey);
            LOGGER.info(i + " signature time:" + (System.currentTimeMillis() - start) + "ms");
            //            Preconditions.checkArgument(SignatureUtil.verify(data, sign, lanPubKey), String.format("data:%s,sign:%s", data, sign));
            if (!SignatureUtil.verify(data, sign, lanPubKey)) {
                n++;
            }
            LOGGER.info(i + " verify time:" + (System.currentTimeMillis() - start) + "ms");
            data += "123";
        }
        LOGGER.info("错误次数:" + n);
    }

    private void sign(String data) {

        String mySign = SignatureUtil.signature(data, lanPriKey);
        // Util 输出
        LOGGER.info("0 ##### sign:" + mySign + "\nresult:" + SignatureUtil.verify(data, mySign, lanPubKey));


        byte[] hash = Sha256Hash.hash(data.getBytes());
        Sha256Hash sha256Hash = Sha256Hash.wrap(hash);

        Wif wif = new Wif(lanPriKey);
        PrivateKey priKey = wif.getPrivateKey();

        ECDSASignature signature = priKey.getKey().sign(sha256Hash);

        Address address = new Address(lanPubKey);
        PublicKey pubKey = address.getPublicKey();

        // 错误验证
        if (!SignatureUtil.verify(data, mySign, lanPubKey)) {
            byte[] signDer = signature.encodeToDER();
            byte[] signDerR = signature.r.toByteArray();
            byte[] signDerS = signature.s.toByteArray();
            Preconditions.checkArgument(pubKey.getKey().verify(hash, signDer));
            Preconditions.checkArgument(signature.isCanonical());

            byte[] mySignData = Util.hexToBytes(mySign);
            BigInteger r = new BigInteger(ByteUtils.subArray(mySignData, 1, 33));
            BigInteger s = new BigInteger(ByteUtils.subArray(mySignData, 33));
            ECDSASignature mySignature = new ECDSASignature(r, s);
            byte[] mySignDer = mySignature.encodeToDER();
            byte[] mySignDerR = mySignature.r.toByteArray();
            byte[] mySignDerS = mySignature.s.toByteArray();
            Preconditions.checkArgument(pubKey.getKey().verify(hash, mySignDer));
        }
        // 计算值 输出
        byte[] sigData;
        int recId = -1;

        for (int i = 0; i < 4; i++) {
            ECKey k = ECKey.recoverFromSignature(i, signature, sha256Hash, priKey.getKey().isCompressed());
            if (k != null && k.getPubKeyPoint().equals(priKey.getKey().getPubKeyPoint())) {
                recId = i;
                break;
            }
        }
        sigData = new byte[65];  // 1 header + 32 bytes for R + 32 bytes for S
        int headerByte = recId + 27 + (priKey.getKey().isCompressed() ? 4 : 0);
        sigData[0] = (byte) headerByte;
        System.arraycopy(Utils.bigIntegerToBytes(signature.r, 32), 0, sigData, 1, 32);
        System.arraycopy(Utils.bigIntegerToBytes(signature.s, 32), 0, sigData, 33, 32);

        LOGGER.info("2 ##### sign:" + Util.bytesToHex(sigData) + "\nresult:"
                + SignatureUtil.verify(data, ByteUtils.toHexString(sigData), pubKey.getAddress()));

    }



}
