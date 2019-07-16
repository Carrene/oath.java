package com.nuesoft.oath;


public interface IChallengeResponse extends IOath {

    String generateOcra(String ocraSuite, byte[] key, String counter,
                        String challenge, String password, String sessionInformation,
                        String timeStamp) throws Exception;
}
