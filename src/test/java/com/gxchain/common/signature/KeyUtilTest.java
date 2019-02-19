package com.gxchain.common.signature;


import com.gxchain.common.signature.crypto.ec.GxcPrivateKey;
import com.gxchain.common.signature.utils.PrivateKey;
import com.gxchain.common.signature.utils.PublicKey;
import org.junit.Test;

/**
 * @author liruobin
 * @since 2018/7/9 下午5:42
 */
public class KeyUtilTest {
    @Test
    public void createKeyPair() throws Exception {
        String brainKey = KeyUtil.suggestBrainKey();
        System.out.println(brainKey);

        PrivateKey privateKey= KeyUtil.getBrainPrivateKey(brainKey,0);
        System.out.println(privateKey.toWif());

        PublicKey publicKey = KeyUtil.getPublicKey(privateKey);
        System.out.println(publicKey.getAddress());
    }
}
