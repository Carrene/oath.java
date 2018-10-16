package com.nuesoft.oath;

import org.junit.Assert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.stream.Stream;

import nuesoft.helpdroid.util.Converter;

@DisplayName("Should pass the method parameters provided by the oneWayFirstTableParameter() method")
public class ChallengeResponseTest {

    private static final String SEED_128 = "3132333435363738393031323334353637383930";
    private static final String SEED_256 = "3132333435363738393031323334353637383930313233343536373839303132";
    private static final String SEED_512 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";

    @ParameterizedTest(name = "{index} => challenge={0}, response={1}")
    @MethodSource("oneWayFirstTableParameter")
    public void testOcra_firstTable(String challenge, String response) throws Exception {

        byte[] secretByte = Converter.hexStringToBytes(SEED_128);
        String hexChallenge = (new BigInteger(challenge, 10)).toString(16).toUpperCase();
        ChallengeResponse challengeResponse = new ChallengeResponse();
        String ocra = challengeResponse.generateOcra("OCRA-1:HOTP-SHA1-6:QN08", secretByte, null, hexChallenge, null, null, null);
        Assert.assertEquals(ocra, response);
    }

    @ParameterizedTest(name = "{index} => counter={0}, challenge={1}, response={2}")
    @MethodSource("oneWaySecondTableParameter")
    public void testOcra_secondTable(String counter, String challenge, String response) throws Exception {

        byte[] secretByte = Converter.hexStringToBytes(SEED_256);
        String hexChallenge = (new BigInteger(challenge, 10)).toString(16).toUpperCase();
        ChallengeResponse challengeResponse = new ChallengeResponse();
        String ocra = challengeResponse.generateOcra("OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", secretByte, counter, hexChallenge, "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", null, null);
        Assert.assertEquals(ocra, response);

    }

    @ParameterizedTest(name = "{index} => challenge={1}, response={2}")
    @MethodSource("oneWayThirdTableParameter")
    public void testOcra_thirdTable(String challenge, String response) throws Exception {

        byte[] secretByte = Converter.hexStringToBytes(SEED_256);
        String hexChallenge = (new BigInteger(challenge, 10)).toString(16).toUpperCase();

        ChallengeResponse challengeResponse = new ChallengeResponse();
        String ocra = challengeResponse.generateOcra("OCRA-1:HOTP-SHA256-8:QN08-PSHA1", secretByte, null, hexChallenge, "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", null, null);
        Assert.assertEquals(ocra, response);
    }


    @ParameterizedTest(name = "{index} => counter={0}, challenge={1}, response={2}")
    @MethodSource("oneWayForthTableParameter")
    public void testOcra_forthTable(String counter, String challenge, String response) throws Exception {

        byte[] secretByte = Converter.hexStringToBytes(SEED_512);
        String hexChallenge = (new BigInteger(challenge, 10)).toString(16).toUpperCase();

        ChallengeResponse challengeResponse = new ChallengeResponse();
        String ocra = challengeResponse.generateOcra("OCRA-1:HOTP-SHA512-8:C-QN08", secretByte, counter, hexChallenge, null, null, null);
        Assert.assertEquals(ocra, response);
    }

    @ParameterizedTest(name = "{index} => counter={0}, time={1}, response={2}")
    @MethodSource("oneWayFifthTableParameter")
    public void testOcra_fifthTable(String question, String time, String response) throws Exception {

        byte[] secretByte = Converter.hexStringToBytes(SEED_512);
        String hexQuestion = (new BigInteger(question, 10)).toString(16).toUpperCase();

        ChallengeResponse challengeResponse = new ChallengeResponse();
        String ocra = challengeResponse.generateOcra("OCRA-1:HOTP-SHA512-8:QN08-T1M", secretByte, null, hexQuestion, null, null, time);
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

    private static Stream<Arguments> oneWaySecondTableParameter() {

        return Stream.of(
                Arguments.of("0", "12345678", "65347737"),
                Arguments.of("1", "12345678", "86775851"),
                Arguments.of("2", "12345678", "78192410"),
                Arguments.of("3", "12345678", "71565254"),
                Arguments.of("4", "12345678", "10104329"),
                Arguments.of("5", "12345678", "65983500"),
                Arguments.of("6", "12345678", "70069104"),
                Arguments.of("7", "12345678", "91771096"),
                Arguments.of("8", "12345678", "75011558"),
                Arguments.of("9", "12345678", "08522129")
        );
    }

    private static Stream<Arguments> oneWayThirdTableParameter() {

        return Stream.of(
                Arguments.of("00000000", "83238735"),
                Arguments.of("11111111", "01501458"),
                Arguments.of("22222222", "17957585"),
                Arguments.of("33333333", "86776967"),
                Arguments.of("44444444", "86807031")
        );
    }

    private static Stream<Arguments> oneWayForthTableParameter() {

        return Stream.of(
                Arguments.of("00000", "00000000", "07016083"),
                Arguments.of("00001", "11111111", "63947962"),
                Arguments.of("00002", "22222222", "70123924"),
                Arguments.of("00003", "33333333", "25341727"),
                Arguments.of("00004", "44444444", "33203315"),
                Arguments.of("00005", "55555555", "34205738"),
                Arguments.of("00006", "66666666", "44343969"),
                Arguments.of("00007", "77777777", "51946085"),
                Arguments.of("00008", "88888888", "20403879"),
                Arguments.of("00009", "99999999", "31409299")
        );
    }

    private static Stream<Arguments> oneWayFifthTableParameter() {

        return Stream.of(
                Arguments.of("00000000", "132d0b6", "95209754"),
                Arguments.of("11111111", "132d0b6", "55907591"),
                Arguments.of("22222222", "132d0b6", "22048402"),
                Arguments.of("33333333", "132d0b6", "24218844"),
                Arguments.of("44444444", "132d0b6", "36209546")
        );
    }
}