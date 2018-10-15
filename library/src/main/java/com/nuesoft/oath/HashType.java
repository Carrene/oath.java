package com.nuesoft.oath;

public enum HashType {

    SHA1("SHA1"),
    SHA256("SHA2"),
    SHA384("SHA3"),
    SHA512("SHA4");

    private final String algorithmCode;

    HashType(String algorithmCode) {

        this.algorithmCode = algorithmCode;
    }

    public static HashType fromCode(String hash) {

        switch (hash) {

            case "SHA-1":
                return SHA1;

            case "SHA-2":
                return SHA256;

            case "SHA-3":
                return SHA384;

            case "SHA-4":
                return SHA512;
        }

        return SHA1;
    }

    public String getCode() {

        return algorithmCode;
    }
}