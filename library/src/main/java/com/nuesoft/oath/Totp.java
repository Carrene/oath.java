package com.nuesoft.oath;

import java.util.Calendar;
import java.util.TimeZone;

public class Totp extends Otp implements ITotp {

    private byte[] mSecret;
    private int mTimeInterval;
    private HashType mHashType;
    private int mOtpLength;

    public Totp(byte[] secret, int timeInterval, int otpLength, HashType hashType) {

        mSecret = secret;
        mTimeInterval = timeInterval;
        mOtpLength = otpLength;
        mHashType = hashType;
    }

    @Override
    public String generateTotp() {

        long time = (Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis()) / 1000;
        return generateTotp(time);
    }

    @Override
    public String generateTotp(long time) {

        long counter = (time / mTimeInterval);
        return super.generateOtp(counter, mHashType, mSecret, mOtpLength);
    }
}