package com.nuesoft.oath;


import com.ehsanmashhadi.helpdroid.crypto.CryptoUtil;
import com.ehsanmashhadi.helpdroid.crypto.HmacType;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class Otp implements IOath {

    static final int[] DIGITS_POWER
            //  0  1   2     3    4        5        6       7         8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    protected String generateOtp(long moveFactor, HashType mHashType, byte[] secret, int otpLength) {

        byte[] counter = new byte[8];
        long movingFactor = moveFactor;

        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        byte[] hmac;
        try {
            hmac = CryptoUtil.hmac(hashTypeToHmacType(mHashType), secret, counter);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        int offset = hmac[hmac.length - 1] & 0xf;
        int otpBinary = ((hmac[offset] & 0x7f) << 24)
                | ((hmac[offset + 1] & 0xff) << 16)
                | ((hmac[offset + 2] & 0xff) << 8)
                | (hmac[offset + 3] & 0xff);

        int otp = otpBinary % DIGITS_POWER[otpLength];
        StringBuilder result = new StringBuilder("" + otp);
        while (result.length() < otpLength) {
            result.insert(0, "0");
        }
        return result.toString();
    }

    private static HmacType hashTypeToHmacType(HashType hashType) {

        switch (hashType) {
            case SHA1:
                return HmacType.HmacSHA1;
            case SHA256:
                return HmacType.HmacSHA256;
            case SHA384:
                return HmacType.HmacSHA384;
            case SHA512:
                return HmacType.HmacSHA512;
            default:
                throw new IllegalArgumentException();
        }
    }
}
