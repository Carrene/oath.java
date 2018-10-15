package com.nuesoft.oath;

public interface ITotp {

    String generateTotp();

    String generateTotp(long time);
}
