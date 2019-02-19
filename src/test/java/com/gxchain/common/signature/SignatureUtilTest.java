package com.gxchain.common.signature;

import org.junit.Test;


/**
 * @author liruobin
 * @since 2018/7/9 下午6:22
 */
public class SignatureUtilTest {
    String privateKey = "5JSwnoEbw9s3Sjb8uefSa4qMvDTZD36qTn4Etb6c2H5T59ZjXhu";
    String publicKey = "GXC7Kba8Mot1uGGd4BhFUkUdUftXgiieygyn2WoC7MJWuoqrmsZPt";
    String data = "1111";

    @Test
    public void signatureAndVerify() throws Exception {
        String sig = SignatureUtil.signature(data, privateKey);
        System.out.println(sig + "\n" + SignatureUtil.verify(data, sig, publicKey));
    }
}