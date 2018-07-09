package com.gxchain.common.signature;

import com.alibaba.fastjson.JSON;
import com.gxchain.common.signature.utils.PrivateKey;
import com.gxchain.common.signature.utils.PublicKey;
import org.apache.commons.lang3.RandomUtils;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * @author liruobin
 * @since 2018/7/4 上午11:38
 */
public class KeyUtil {
    /**
     * 生成脑key
     *
     * @return
     * @throws IOException
     */
    public static String suggestBrainKey() throws IOException {

        String dictionary = (String) JSON.parseObject(readDictionary()).get("en");
        String[] dictionaryLines = dictionary.split(",");
        if (dictionaryLines.length != 49744) {
            throw new RuntimeException("expecting 49744 but got " + dictionaryLines.length + " dictionary words");
        }
        int end = 16;
        List<String> brainkey = new ArrayList<>();
        for (int i = 0; i < end; i ++) {
            int wordIndex = RandomUtils.nextInt(0, dictionaryLines.length - 1);
            brainkey.add(dictionaryLines[wordIndex]);
        }
        return join(join(brainkey, " ").split("[\\t\\n\\v\\f\\r ]+"), " ");
    }

    /**
     * 格式化脑key
     *
     * @param brainKey
     * @return
     */
    private static String normalizeBrainKey(String brainKey) {
        return join(brainKey.trim().split("[\\t\\n\\v\\f\\r ]+"), " ");
    }

    /**
     * 由脑key生成私钥
     *
     * @param brainKey
     * @return
     */
    public static PrivateKey getBrainPrivateKey(String brainKey, int seq) {
        brainKey = normalizeBrainKey(brainKey);
        return PrivateKey.fromBuffer(Sha256Hash.hash(sha512(String.format("%s %d", brainKey, seq))));
    }

    /**
     * 获取公钥
     *
     * @param privateKey 私钥
     * @return
     */
    public static PublicKey getPublicKey(PrivateKey privateKey) {
        return new PublicKey(ECKey.fromPublicOnly(privateKey.getKey().getPubKey()));
    }

    private static byte[] sha512(String content) {
        try {
            MessageDigest hasher = MessageDigest.getInstance("sha-512");
            hasher.update(content.getBytes());
            return hasher.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @return
     * @throws IOException
     */
    private static String readDictionary() throws IOException {
        InputStream inputStream = KeyUtil.class.getResourceAsStream("/dictionary_en.json");

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = inputStream.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        String str = result.toString(StandardCharsets.UTF_8.name());
        return str;
    }


    private static String join(List<String> sources, String separator) {
        if (sources == null || sources.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (String result : sources) {
            builder.append(separator).append(result);
        }
        return builder.toString().substring(separator.length());
    }

    private static String join(String[] sources, String separator) {
        if (sources == null || sources.length == 0) {
            return "";
        }
        return join(Arrays.asList(sources), separator);
    }
}
