package com.nuesoft.oath;

import java.util.Arrays;
import java.util.Calendar;
import java.util.TimeZone;

import static java.lang.System.arraycopy;

//TODO(Ehsan) Should be refactored
public class ChallengeResponse implements IChallengeResponse {


    private String mSeed;
    private int mTimeInterval;
    private HashType mHashType;
    private int mResponseLength;
    //TODO is this field necessary?
    private long mCounter;


    @Override
    public String generateHashChallengeResponse(String challenge) {

        String ocraSuite = buildOcraSuit("1", 40);

        byte[] counter = new byte[8];
        long movingFactor = mCounter;

        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // Build question buffer
        byte[] question = new byte[128];
        Arrays.fill(question, (byte) 0);
        arraycopy(challenge.getBytes(), 0, question, 0, Math.min(challenge.length(), question.length));

        // Build message
        int messageLength = ocraSuite.length() + question.length + counter.length + 1;
        byte[] message = new byte[messageLength];

        // put bytes of Ocra Suite into message
        arraycopy(ocraSuite.getBytes(), 0, message, 0, ocraSuite.length());

        // add delimeter
        message[ocraSuite.length()] = (byte) (0x00);

        // put question to message
        arraycopy(question, 0, message, ocraSuite.length() + 1, question.length);

        // put timeStamp to message
        arraycopy(counter, 0, message, ocraSuite.length() + 1 + question.length, counter.length);

        byte[] seed = mSeed.getBytes();

//        HashType hashType = HashType.fromCode(mHashType);
//        byte[] hash = HMAC(hashType, seed, message);

//        int offset = hash[hash.length - 1] & 0xf;
//
//        int responseBinary = ((hash[offset] & 0x7f) << 24)
//                | ((hash[offset + 1] & 0xff) << 16)
//                | ((hash[offset + 2] & 0xff) << 8)
//                | (hash[offset + 3] & 0xff);


//        int otp = responseBinary % DIGITS_POWER[mResponseLength];
//        StringBuilder result = new StringBuilder(Integer.toString(otp));

//        while (result.length() < mResponseLength) {
//            result.insert(0, "0");
//        }

//        return result.toString();
        return null;
    }

    @Override
    public String generateHashTimeChallengeResponse(String challenge) {

        long time = (Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis()) / 1000;
        mCounter = (time / mTimeInterval);
        String TOTP = generateHashChallengeResponse(challenge);
        return TOTP;
    }

    @Override
    public String generateHashTimeChallengeResponse(String challenge, long time) {

        return null;
    }

    @Override
    public boolean verifyChallengeResponse(String challenge, String response, int windowSize) {

        boolean result = false;
        int offset = 0;
        Calendar currentTime = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        int timeStep = mTimeInterval;
        while (offset < windowSize) {
            String tempResponse = generateHashTimeChallengeResponse(challenge, currentTime);
            if (tempResponse.equals(response)) {
                result = true;
                return result;
            }
            offset += timeStep;
            currentTime.add(Calendar.SECOND, offset);
        }

        offset = 0;
        currentTime = Calendar.getInstance(TimeZone.getTimeZone("GMT"));

        while (offset > -windowSize) {
            String tempResponse = generateHashTimeChallengeResponse(challenge, currentTime);
            if (tempResponse.equals(response)) {
                result = true;
                return result;
            }
            offset -= timeStep;
            currentTime.add(Calendar.SECOND, offset);
        }
        return result;
    }

    private String generateHashTimeChallengeResponse(String challenge, Calendar currentTime) {

        long time = (Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis()) / 1000;
        mCounter = (time / mTimeInterval);
        String TOTP = generateHashChallengeResponse(challenge);
        return TOTP;
    }

    private String formatTime(int timeInterval) {

        if (timeInterval >= 60) {

            timeInterval /= 60;

            if (timeInterval > 60) {
                timeInterval /= 60;
                return timeInterval + "H";
            }

            return timeInterval + "M";
        }

        return timeInterval + "S";
    }

    private String buildOcraSuit(String version, int challengeLimit) {

        String algorithm = "OCRA-" + version;
//        algorithm += " : HOTP-" + HashType.fromCode(mHashType);
        algorithm += "-" + mResponseLength;

        if (mCounter != 0) {
            algorithm += " : C-QA" + challengeLimit;
        } else if (mTimeInterval != 0) {
            algorithm += " : QA" + challengeLimit + "-T" + formatTime(mTimeInterval);
        }
        return algorithm;
    }
}
