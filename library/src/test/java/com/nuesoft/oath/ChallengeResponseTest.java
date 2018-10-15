package com.nuesoft.oath;

import org.junit.Assert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.stream.Stream;

@DisplayName("Should pass the method parameters provided by the oneWayFirstTableParameter() method")
public class ChallengeResponseTest {

    String seed128 = "3132333435363738393031323334353637383930";

    @ParameterizedTest(name = "{index} => challenge={0}, response={1}")
    @MethodSource("oneWayFirstTableParameter")
    public void testOcra_firstTable(String challenge, String response) throws Exception {

        ChallengeResponse challengeResponse = new ChallengeResponse();
        String hexChallenge = (new BigInteger(challenge, 10)).toString(16).toUpperCase();
        String ocra = challengeResponse.generateOCRA("OCRA-1:HOTP-SHA1-6:QN08", seed128, null, hexChallenge, null, null, null);
        Assert.assertEquals(ocra, response);
    }

    private static Stream<Arguments> oneWayFirstTableParameter() {

        return Stream.of(
                Arguments.of("00000000", "237653"),
                Arguments.of("11111111", "243178"),
                Arguments.of("22222222", "653583"),
                Arguments.of("33333333", "740991"),
                Arguments.of("44444444", "608993"),
                Arguments.of("55555555", "388898"),
                Arguments.of("66666666", "816933"),
                Arguments.of("77777777", "224598"),
                Arguments.of("88888888", "750600"),
                Arguments.of("99999999", "294470")
        );
    }
}
