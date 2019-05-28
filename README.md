
# OATH library in Java

[![OATH](https://jitpack.io/v/Carrene/oath.java.svg)](https://jitpack.io/#Carrene/oath.java)

## Download

1. **Add the JitPack repository to your build file**

 Add it in your project level build.gradle:
```
    allprojects {
        repositories {
            ...
            maven { url 'https://jitpack.io' }
        }
    }
```

2. **Add the dependency**
Add in in your app module level build.gradle
```
    dependencies {
	        implementation 'com.github.Carrene:oath.java:0.2.0'
    }
```
## How to use

### Simple usage
```JAVA
        String hexSecret = "3132333435363738393031323334353637383930";
        byte[] secret = Converter.hexStringToBytes(hexSecret);
        //Totp(Secret,Time interval, OTP length, Hash type);
        Totp otp = new Totp(secret, 30, 8, HashType.SHA1);
        String totp = otp.generateTotp();
```
```java
 public static byte[] hexStringToBytes(String hex) throws Exception {

        int length = hex.length();
        if (length % 2 != 0) {
            throw new Exception("Illegal string length: " + length);
        }

        int bytesLength = length / 2;
        byte[] bytes = new byte[bytesLength];
        int idxChar = 0;
        for (int i = 0; i < bytesLength; i++) {
            int value = parseHexDigit(hex.charAt(idxChar++)) << 4;
            value |= parseHexDigit(hex.charAt(idxChar++));
            bytes[i] = (byte) value;
        }
        return bytes;
    }
```
