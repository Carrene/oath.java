package com.nuesoft.oath;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.TimeZone;

import nuesoft.helpdroid.crypto.CryptoUtil;
import nuesoft.helpdroid.crypto.HmacType;
import nuesoft.helpdroid.util.Converter;

import static java.lang.System.arraycopy;

//TODO(Ehsan) Should be refactored
public class ChallengeResponse implements IChallengeResponse {


    private String mSeed;
    private int mTimeInterval;
    private HashType mHashType;
    private int mResponseLength;
    //TODO is this field necessary?
    private long mCounter;

    public String generateOCRA(String ocraSuite, String key, String counter, String question, String password, String sessionInformation, String timeStamp) throws Exception {

        int codeDigits = 0;
        HmacType crypto = null;
        String result = null;
        int ocraSuiteLength = (ocraSuite.getBytes()).length;
        int counterLength = 0;
        int questionLength = 0;
        int passwordLength = 0;
        int sessionInformationLength = 0;
        int timeStampLength = 0;

        // The OCRASuites components
        String CryptoFunction = ocraSuite.split(":")[1];
        String DataInput = ocraSuite.split(":")[2];


        if (CryptoFunction.toLowerCase().indexOf("sha1") > 1)
            crypto = HmacType.HmacSHA1;
        if (CryptoFunction.toLowerCase().indexOf("sha256") > 1)
            crypto = HmacType.HmacSHA256;
        if (CryptoFunction.toLowerCase().indexOf("sha512") > 1)
            crypto = HmacType.HmacSHA512;

        // How many digits should we return
        codeDigits = Integer.decode(CryptoFunction.substring(
                CryptoFunction.lastIndexOf("-") + 1));

        // The size of the byte array message to be encrypted
        // Counter
        if (DataInput.toLowerCase().startsWith("c")) {
            // Fix the length of the HEX string
            while (counter.length() < 16)
                counter = "0" + counter;
            counterLength = 8;
        }
        // Question - always 128 bytes
        if (DataInput.toLowerCase().startsWith("q") ||
                (DataInput.toLowerCase().indexOf("-q") >= 0)) {
            while (question.length() < 256)
                question = question + "0";
            questionLength = 128;
        }

        // Password - sha1
        if (DataInput.toLowerCase().indexOf("psha1") > 1) {
            while (password.length() < 40)
                password = "0" + password;
            passwordLength = 20;
        }

        // Password - sha256
        if (DataInput.toLowerCase().indexOf("psha256") > 1) {
            while (password.length() < 64)
                password = "0" + password;
            passwordLength = 32;
        }

        // Password - sha512
        if (DataInput.toLowerCase().indexOf("psha512") > 1) {
            while (password.length() < 128)
                password = "0" + password;
            passwordLength = 64;
        }

        // sessionInformation - s064
        if (DataInput.toLowerCase().indexOf("s064") > 1) {
            while (sessionInformation.length() < 128)
                sessionInformation = "0" + sessionInformation;
            sessionInformationLength = 64;
        }

        // sessionInformation - s128
        if (DataInput.toLowerCase().indexOf("s128") > 1) {
            while (sessionInformation.length() < 256)
                sessionInformation = "0" + sessionInformation;
            sessionInformationLength = 128;
        }

        // sessionInformation - s256
        if (DataInput.toLowerCase().indexOf("s256") > 1) {
            while (sessionInformation.length() < 512)
                sessionInformation = "0" + sessionInformation;
            sessionInformationLength = 256;
        }

        // sessionInformation - s512
        if (DataInput.toLowerCase().indexOf("s512") > 1) {
            while (sessionInformation.length() < 1024)

                sessionInformation = "0" + sessionInformation;
            sessionInformationLength = 512;
        }

        // TimeStamp
        if (DataInput.toLowerCase().startsWith("t") ||
                (DataInput.toLowerCase().indexOf("-t") > 1)) {
            while (timeStamp.length() < 16)
                timeStamp = "0" + timeStamp;
            timeStampLength = 8;
        }

        // Remember to add "1" for the "00" byte delimiter
        byte[] msg = new byte[ocraSuiteLength +
                counterLength +
                questionLength +
                passwordLength +
                sessionInformationLength +
                timeStampLength +
                1];


        // Put the bytes of "ocraSuite" parameters into the message
        byte[] bArray = ocraSuite.getBytes();
        System.arraycopy(bArray, 0, msg, 0, bArray.length);

        // Delimiter
        msg[bArray.length] = 0x00;

        // Put the bytes of "Counter" to the message
        // Input is HEX encoded
        if (counterLength > 0) {
            bArray = Converter.hexStringToBytes(counter);
            System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1,
                    bArray.length);
        }


        // Put the bytes of "question" to the message
        // Input is text encoded
        if (questionLength > 0) {
            bArray = Converter.hexStringToBytes(question);
            System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 +
                    counterLength, bArray.length);
        }

        // Put the bytes of "password" to the message
        // Input is HEX encoded
        if (passwordLength > 0) {
            bArray = Converter.hexStringToBytes(password);
            System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 +
                    counterLength + questionLength, bArray.length);

        }

        // Put the bytes of "sessionInformation" to the message
        // Input is text encoded
        if (sessionInformationLength > 0) {
            bArray = Converter.hexStringToBytes(sessionInformation);
            System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 +
                    counterLength + questionLength +
                    passwordLength, bArray.length);
        }

        // Put the bytes of "time" to the message
        // Input is text value of minutes
        if (timeStampLength > 0) {
            bArray = Converter.hexStringToBytes(timeStamp);
            System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 +
                            counterLength + questionLength +
                            passwordLength + sessionInformationLength,
                    bArray.length);
        }

        bArray = Converter.hexStringToBytes(key);

        byte[] hash = CryptoUtil.hmac(crypto, bArray, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary =
                ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }


    @Override
    public String generateHashChallengeResponse(String challenge) {

        String ocraSuite = buildOcraSuit("1", 8);

        byte[] counter = new byte[8];
        long movingFactor = mCounter;

        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // Build question buffer
        byte[] question = new byte[8];
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

        HashType hashType = mHashType;
        byte[] hash = new byte[0];
        try {
            hash = CryptoUtil.hmac(HmacType.HmacSHA1, seed, message);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        int offset = hash[hash.length - 1] & 0xf;

        int responseBinary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);


        int otp = responseBinary % DIGITS_POWER[mResponseLength];
        StringBuilder result = new StringBuilder(Integer.toString(otp));

        while (result.length() < mResponseLength) {
            result.insert(0, "0");
        }

        return result.toString();
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
        algorithm += " : HOTP-" + mHashType.toString();
        algorithm += "-" + mResponseLength;

        if (mCounter != 0) {
            algorithm += " : C-QA" + challengeLimit;
        } else if (mTimeInterval != 0) {
            algorithm += " : QA" + challengeLimit + "-T" + formatTime(mTimeInterval);
        }
        return algorithm;
    }
}
