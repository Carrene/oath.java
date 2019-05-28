package com.nuesoft.oath;


import com.ehsanmashhadi.helpdroid.crypto.CryptoUtil;
import com.ehsanmashhadi.helpdroid.crypto.HmacType;
import com.ehsanmashhadi.helpdroid.util.Converter;

public class ChallengeResponse implements IChallengeResponse {

    static final int[] DIGITS_POWER
            //  0  1   2     3    4        5        6       7         8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    @Override
    public String generateOcra(String ocraSuite, byte[] secret, String counter, String challenge, String password, String sessionInformation, String timeStamp) throws Exception {

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
            while (challenge.length() < 256)
                challenge = challenge + "0";
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
            bArray = Converter.hexStringToBytes(challenge);
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

        bArray = secret;

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
}
