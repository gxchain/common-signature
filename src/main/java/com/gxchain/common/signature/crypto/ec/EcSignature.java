/*
 * Copyright (c) 2017 Mithril coin.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.gxchain.common.signature.crypto.ec;


import com.gxchain.common.signature.crypto.util.HexUtils;

import java.math.BigInteger;
import java.util.Arrays;


/**
 * Created by swapnibble on 2017-09-20.
 */

public class EcSignature {
    public int recId = -1;

    public final BigInteger r;
    public final BigInteger s;
    public final CurveParam curveParam;

    public EcSignature(BigInteger r, BigInteger s, CurveParam curveParam) {
        this.r = r;
        this.s = s;
        this.curveParam = curveParam;
    }

    public EcSignature(BigInteger r, BigInteger s, CurveParam curveParam, int recId) {
        this(r, s, curveParam);

        setRecid(recId);
    }

    public void setRecid(int recid) {
        this.recId = recid;
    }


    @Override
    public boolean equals(Object other) {
        if (this == other)
            return true;

        if (null == other || getClass() != other.getClass())
            return false;

        EcSignature otherSig = (EcSignature) other;
        return r.equals(otherSig.r) && s.equals(otherSig.s);
    }

    public boolean isRSEachLength(int length) {
        return (r.toByteArray().length == length) && (s.toByteArray().length == length);
    }


    public byte[] encoding(boolean compressed) {
        if (recId < 0 || recId > 3) {
            throw new IllegalStateException("signature has invalid recid.");
        }

        int headerByte = recId + 27 + (compressed ? 4 : 0);
        byte[] sigData = new byte[65]; // 1 header + 32 bytes for R + 32 bytes for S
        sigData[0] = (byte) headerByte;
        System.arraycopy(EcTools.integerToBytes(this.r, 32), 0, sigData, 1, 32);
        System.arraycopy(EcTools.integerToBytes(this.s, 32), 0, sigData, 33, 32);
        return sigData;
    }

    public static EcSignature decoding(boolean compressed, byte[] data) {
        int headerByte = data[0];
        int recId = headerByte - 27 - (compressed ? 4 : 0);
        BigInteger r = new BigInteger(Arrays.copyOfRange(data, 1, 33));
        BigInteger s = new BigInteger(Arrays.copyOfRange(data, 33, 65));
        return new EcSignature(r, s, null, recId);
    }

    @Override
    public String toString() {
        if (recId < 0 || recId > 3) {
            return "no recovery sig: " + HexUtils.toHex(this.r.toByteArray()) + HexUtils.toHex(this.s.toByteArray());
        }

        return HexUtils.toHex(encoding(true));
    }

    /**
     * https://docs.gxchain.org/advanced/signature.html
     * @return
     */
    public boolean isFCCanonical() {
        byte[] byte_r = r.toByteArray();
        byte[] byte_s = s.toByteArray();

        return !((byte_r[0] & 0x80) > 0)
                && !(byte_r[0] == 0 && !((byte_r[1] & 0x80) > 0))
                && !((byte_s[0] & 0x80) > 0)
                && !(byte_s[0] == 0 && !((byte_s[1] & 0x80) > 0));
    }
}
