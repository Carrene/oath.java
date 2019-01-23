package com.nuesoft.oath;

import com.ehsanmashhadi.helpdroid.util.Converter;

import org.junit.Assert;
import org.junit.Test;


/**
 * https://tools.ietf.org/html/rfc4226
 */
public class HotpTest {

    @Test
    public void testHotp_10time() throws Exception {

        String hexSecret = "3132333435363738393031323334353637383930";
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        Hotp hotp = new Hotp(secret, 6, HashType.SHA1);
        Assert.assertEquals(hotp.generateHotp(), "755224");
        Assert.assertEquals(hotp.generateHotp(), "287082");
        Assert.assertEquals(hotp.generateHotp(), "359152");
        Assert.assertEquals(hotp.generateHotp(), "969429");
        Assert.assertEquals(hotp.generateHotp(), "338314");
        Assert.assertEquals(hotp.generateHotp(), "254676");
        Assert.assertEquals(hotp.generateHotp(), "287922");
        Assert.assertEquals(hotp.generateHotp(), "162583");
        Assert.assertEquals(hotp.generateHotp(), "399871");
        Assert.assertEquals(hotp.generateHotp(), "520489");
    }
}

