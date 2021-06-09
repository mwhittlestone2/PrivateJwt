package dk.tdcnet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.*;

class JwtCreatorTest {

    private static String privateJWTForTesting = "-----BEGIN RSA PRIVATE KEY-----" +
            "MIIEogIBAAKCAQEAusrdmYjemTmxmxmbeEJmFGmfdLubQwa1273O4F/2aeIF4qra" +
            "A98Q5W1i2f/IxZLjliTj/Jl9vjrHsQWpArl+ZYYi7GpONQAZQ7+FSmVDstJy+mNN" +
            "FsOeldP218jLQpSGO8b9SPNz3fZAL9OzTti3ShU0D6ubp3bBke2tQ8xyYOTkFKMP" +
            "LdtYKlO5S5EhmNTQIkZiJhEGzP1yC3YuJ06Vie60cdGTCiWbiaG/Scio62su5N4E" +
            "Y5kAknd+0rWk4q4AAug9U5A/Uvkj1ejyM2Iy8JDNSUjLaybks73TYc56peVWilWd" +
            "BLpj8rR/fYepPU8jDF784a9WSFYzorH/dndkbwIDAQABAoIBAAwLaiTTatZPhMPL" +
            "1jbeQgED9IvAgyXClRxuJ0/xicA3GldzQKtqPIeThgHCzBPtWyG13EIDNbsvK1Kf" +
            "Wxzfw1lrJlPyenuEngLWPGAmAN3TH/KqtfBUI3HLoRZpJ+FYFjXDKL1Sl9osREqx" +
            "NTxnngRq/8t/SDV3fP2naUcLZyUXN4EFRK3I8k7JJ0JcAV2xlOHw8d4cE5BNRVPB" +
            "fa/iOKhQJcLESML5pfQ3lIJu12IUmpwDiM9WgrnLPEMLaBb1vBBfhDUTJuWmTVgP" +
            "t9QBHh+bTgbNRHodU/RPsA60BOiBJ3BxPx1D3tE0i9uPz0QYNneEzGg98zWN/skT" +
            "rLXiAo0CgYEA3hG2zNj/zs3D2SpleBwlD736y+EuZNz0op9EhwL8/7jHfxTqCdzv" +
            "LgW4J2AaahhwXrYx2cHdy2rjRTMTqRT7Zdg76Obhg7VTqIOA/ZWZ+dol80qwvfI2" +
            "1MCbcl09l3P452nfsmt6f9gcqAJdFLjPAixs4iZRH9wFUHtmR9PokzUCgYEA11VL" +
            "J+XQqDTTHYHbQqR4yKQn4Z0cDoz623CaXejg1VyyNtP7QjLpmAswX0CuTIgkNqBF" +
            "9/isOP66HR9YzvJpuwMWCn6j/ObIg8yQx7z6ORqxSmLPUejNYgBZnE6O76eWjIH7" +
            "Ms7QdRawIUim0c4OfCKGII6giYfoytUyGvmGCZMCgYAcTOWe9YikMlTjOCP2Sp/u" +
            "gaeUk/31nLMQhnuVOSxE6qeB6oho+V8B3ni5i+XR34tyhoWT2sEJS3XrO7cltSbU" +
            "s9nutH3I6zLeJuQpbQdScBqmBr6/dj7GnkUxLfDLfFwcIcIAWvIhmMkOID78hRDc" +
            "lgzKRVfRV5jVyOQgA0GAgQKBgFzH5YAlZ4hyalyWbTEDyP86q+xsU4B5gkU2+Wxp" +
            "QSbtr+Qr5mEZqsjWWVtRdUiIiIH5AOzdeud76hlOPme8z43CwKZ49pOrpM4VQHSv" +
            "mmksdSOF+6phUs1dNT9CIhhk71tPTjsQHYW15uIQecCAtoEKJxy0F7vqkYWD4vj4" +
            "dqZ9AoGAF7JWQKjoFccOccwBWUCc6zvBPVNBZXu6rT+zvv7EPahZ1UYoEMmkZKcR" +
            "6M+i4a6fDlEsuwSrWNSMucl2yvFO8gYFyte/z7sJVp+oAglzsrfbNnTinAC571BT" +
            "kmDzYQPB+9DKmpdHPh0f0E1rqu66k9WDPMCYUFITvCd/+51Jevo=" +
            "-----END RSA PRIVATE KEY-----";

    @Test
    void createJwtFromResource() {
        try {
            String fileName = "C:\\keys\\privatekey.pem";
            JwtCreator jwtCreator = new JwtCreator();
            //InputStream inputStream = classLoader.getResourceAsStream(fileName);
            //BufferedReader br = new BufferedReader(new InputStreamReader(classLoader.getResourceAsStream(fileName), "UTF-8"));
            String pem = "";
            //pem = jwtCreator.getPrivateKey(fileName);
            pem = jwtCreator.getPrivateKey(fileName);
            // the stream holding the file content
            if (pem == null) {
                pem = privateJWTForTesting;
                //throw new IllegalArgumentException("file not found! " + fileName);
            }
            PrivateKeyConverter privateKeyConverter = new PrivateKeyConverter();
            //PrivateKey pkCS8 = privateKeyConverter.ReadPEM(fileName);
            //BufferedReader br2 = new BufferedReader(new InputStreamReader(classLoader.getResourceAsStream(fileName), "UTF-8"));
            PrivateKey pkCS8 = privateKeyConverter.ReadPEM(fileName);

            String privateFile = jwtCreator.removeTopAndBottomFromPemFile(pem);
            String tokenEndpoint = "https://fedtest.tdk.dk/as/token.oauth2";
            String client = "abc123";
            String kid = "asdfasdfasdf";
            String output = jwtCreator.createJwt(pkCS8, tokenEndpoint, client, kid);
            assertNotNull(output);
        }
        catch (Exception e) {
            //throw new Exception(e.getMessage());
            Assertions.fail("it failed");
            return;
        }
    }
    @Test
    void createJwtFromFile() {
        try {

            String fileName = "privatekey.pem";

            JwtCreator jwtCreator = new JwtCreator();
            // The class loader that loaded the class
            ClassLoader classLoader = getClass().getClassLoader();
            InputStream inputStream = classLoader.getResourceAsStream(fileName);
            BufferedReader br = new BufferedReader(new InputStreamReader(classLoader.getResourceAsStream(fileName), "UTF-8"));
            String pem = "";
            //pem = jwtCreator.getPrivateKey(fileName);
            pem = jwtCreator.getPrivateKey(br);
            // the stream holding the file content
            if (pem == null) {
                pem = privateJWTForTesting;
                //throw new IllegalArgumentException("file not found! " + fileName);
            }
            PrivateKeyConverter privateKeyConverter = new PrivateKeyConverter();
            //PrivateKey pkCS8 = privateKeyConverter.ReadPEM(fileName);
            BufferedReader br2 = new BufferedReader(new InputStreamReader(classLoader.getResourceAsStream(fileName), "UTF-8"));
            PrivateKey pkCS8 = privateKeyConverter.ReadPEM(br2);

            String privateFile = jwtCreator.removeTopAndBottomFromPemFile(pem);
            String tokenEndpoint = "https://fedtest.tdk.dk/as/token.oauth2";
            String client = "abc123";
            String kid = "asdfasdfasdf";
            String output = jwtCreator.createJwt(pkCS8, tokenEndpoint, client, kid);
            assertNotNull(output);
        }
        catch (Exception e) {
            //throw new Exception(e.getMessage());
            Assertions.fail("it failed");
            return;
        }
    }

}