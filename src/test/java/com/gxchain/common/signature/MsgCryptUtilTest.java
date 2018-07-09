package com.gxchain.common.signature;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @author liruobin
 * @since 2018/7/9 下午6:34
 */
public class MsgCryptUtilTest {
    String privateKey1 = "5K7nFgxt99yTz793yvRh5JhsBF69tsJ6JrXPrQdRD7jGGXmM5gT";
    String publicKey1 = "GXC5uxQkqkv6wGowANEqg1FJdqPycoo5z2tNd89JkUs3xKoMUAZ2E";

    String privateKey2 = "5KPiW8BFkyBVaqFFQXqoCZR3mDrt5M6YfbsJtqUEEUsfwT3kQTn";
    String publicKey2 = "GXC6RrtHmAhgJErs6BWZUDL2VQ9uJfAq1airK4wxLzkxeENTjEvth";

    String data = "test";
    @Test
    public void encryptAndDecrypt() throws Exception {
        long nonce= 2132131232L;
        String s = MsgCryptUtil.encrypt(privateKey1,publicKey2,nonce,data);
        System.out.println(s);
        System.out.println(MsgCryptUtil.decrypt(privateKey2,publicKey1,nonce,s));
    }
}