package com.nuesoft.oath;

import org.junit.Assert;
import org.junit.Test;

import nuesoft.helpdroid.util.Converter;

/**
 * RFC https://tools.ietf.org/html/rfc6238
 */
public class TotpTest {

    String seed128 = "3132333435363738393031323334353637383930";
    String seed256 = "3132333435363738393031323334353637383930" + "313233343536373839303132";
    String seed512 = "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930" + "31323334";

    @Test
    public void testTotp_rfcTestCase1() throws Exception {

        String hexSecret = seed128;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA1);
        String totp = otp.generateTotp(59);
        Assert.assertEquals(totp, "94287082");
    }

    @Test
    public void testTotp_rfcTestCase2() throws Exception {

        String hexSecret = seed256;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA256);
        String totp = otp.generateTotp(59);
        Assert.assertEquals(totp, "46119246");
    }

    @Test
    public void testTotp_rfcTestCase3() throws Exception {

        String hexSecret = seed512;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA512);
        String totp = otp.generateTotp(59);
        Assert.assertEquals(totp, "90693936");
    }

    @Test
    public void testTotp_rfcTestCase4() throws Exception {

        String hexSecret = seed128;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA1);
        String totp = otp.generateTotp(1111111109);
        Assert.assertEquals(totp, "07081804");
    }

    @Test
    public void testTotp_rfcTestCase5() throws Exception {

        String hexSecret = seed256;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA256);
        String totp = otp.generateTotp(1111111109);
        Assert.assertEquals(totp, "68084774");
    }

    @Test
    public void testTotp_rfcTestCase6() throws Exception {

        String hexSecret = seed512;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA512);
        String totp = otp.generateTotp(1111111109);
        Assert.assertEquals(totp, "25091201");
    }

    @Test
    public void testTotp_rfcTestCase7() throws Exception {

        String hexSecret = seed128;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA1);
        String totp = otp.generateTotp(1111111111);
        Assert.assertEquals(totp, "14050471");
    }


    @Test
    public void testTotp_rfcTestCase8() throws Exception {

        String hexSecret = seed256;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA256);
        String totp = otp.generateTotp(1111111111);
        Assert.assertEquals(totp, "67062674");
    }

    @Test
    public void testTotp_rfcTestCase9() throws Exception {

        String hexSecret = seed512;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA512);
        String totp = otp.generateTotp(1111111111);
        Assert.assertEquals(totp, "99943326");
    }

    @Test
    public void testTotp_rfcTestCase10() throws Exception {

        String hexSecret = seed128;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA1);
        String totp = otp.generateTotp(1234567890);
        Assert.assertEquals(totp, "89005924");
    }

    @Test
    public void testTotp_rfcTestCase11() throws Exception {

        String hexSecret = seed256;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA256);
        String totp = otp.generateTotp(1234567890);
        Assert.assertEquals(totp, "91819424");
    }

    @Test
    public void testTotp_rfcTestCase12() throws Exception {

        String hexSecret = seed512;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA512);
        String totp = otp.generateTotp(1234567890);
        Assert.assertEquals(totp, "93441116");
    }

    @Test
    public void testTotp_rfcTestCase13() throws Exception {

        String hexSecret = seed128;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA1);
        String totp = otp.generateTotp(2000000000);
        Assert.assertEquals(totp, "69279037");
    }

    @Test
    public void testTotp_rfcTestCase14() throws Exception {

        String hexSecret = seed256;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA256);
        String totp = otp.generateTotp(2000000000);
        Assert.assertEquals(totp, "90698825");
    }

    @Test
    public void testTotp_rfcTestCase15() throws Exception {

        String hexSecret = seed512;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA512);
        String totp = otp.generateTotp(2000000000);
        Assert.assertEquals(totp, "38618901");
    }

    @Test
    public void testTotp_now8DigitNotNull() throws Exception {

        String hexSecret = seed128;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA1);
        String totp = otp.generateTotp();
        Assert.assertNotNull(totp);
    }

    @Test
    public void testTotp_sha384NowNotNull() throws Exception {

        String hexSecret = seed128;
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA384);
        String totp = otp.generateTotp();
        Assert.assertNotNull(totp);
    }
}