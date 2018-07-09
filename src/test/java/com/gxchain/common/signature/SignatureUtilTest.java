package com.gxchain.common.signature;

import org.junit.Test;


/**
 * @author liruobin
 * @since 2018/7/9 下午6:22
 */
public class SignatureUtilTest {
    String privateKey = "5K7nFgxt99yTz793yvRh5JhsBF69tsJ6JrXPrQdRD7jGGXmM5gT";
    String publicKey = "GXC5uxQkqkv6wGowANEqg1FJdqPycoo5z2tNd89JkUs3xKoMUAZ2E";
    String data = "test";

    @Test
    public void signatureAndVerify() throws Exception {
        String sig = SignatureUtil.signature(data, privateKey);

        System.out.println(sig + "\n" + SignatureUtil.verify(data, sig, publicKey));
    }

}