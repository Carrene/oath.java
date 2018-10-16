package com.nuesoft.oath;


/**
 * Created by NueMD on 2016-06-18.
 */
public interface IChallengeResponse extends IOath {

    String generateOcra(String ocraSuite, byte[] key, String counter, String challenge, String password, String sessionInformation, String timeStamp) throws Exception;

}
