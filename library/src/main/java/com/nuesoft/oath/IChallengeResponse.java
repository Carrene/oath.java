package com.nuesoft.oath;


/**
 * Created by NueMD on 2016-06-18.
 */
public interface IChallengeResponse extends IOath {

    String generateHashChallengeResponse(String challenge);

    String generateHashTimeChallengeResponse(String challenge);

    String generateHashTimeChallengeResponse(String challenge, long time);

    boolean verifyChallengeResponse(String challenge, String response, int windowSize);
}
