package com.nuesoft.oath;

public class Hotp extends Otp implements IHotp {

    private byte[] mSecret;
    private HashType mHashType;
    private int mOtpLength;
    private long mCounter;

    public Hotp(byte[] secret, int otpLength, HashType hashType) {

        mSecret = secret;
        mOtpLength = otpLength;
        mHashType = hashType;
    }

    @Override
    public String generateHotp() {

        long movingFactor = mCounter;
        mCounter++;
        return super.generateOtp(movingFactor, mHashType, mSecret, mOtpLength);
    }
}
