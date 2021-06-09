package dk.tdcnet;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtCreator {

    public String createJwt(PrivateKey privKey, String idpTokenEndPoint, String clientId, String kid) {
        String ret = "";
        try {
            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);
            long ttlMins = 59; //Must be less than 60
            long expMillis = nowMillis + (ttlMins * 60 * 1000);
            Date exp = new Date(expMillis);
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
            Map<String, Object> jwtHeader = new HashMap<String, Object>();
            jwtHeader.put("kid", kid);
            jwtHeader.put("typ", "JWT");
            JTI random = new JTI();
            String jti = random.nextRandomString();

            //hd.put("")
            JwtBuilder builder = Jwts.builder().setHeader(jwtHeader)
                    .setId(jti)
                    .setAudience(idpTokenEndPoint)
                    .setSubject(clientId) //Subject and Issuer must be the same - ClientId created in IdP
                    .setIssuer(clientId)
                    .setIssuedAt(now)
                    .setNotBefore(now)
                    .setExpiration(exp)
                    .signWith(signatureAlgorithm, privKey)
                    ;

            ret = builder.compact();


        }
        catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            return null;
        }
        return ret;
    }
    /*
    * remoteTopAndBottomFromPemFile allows full pem file to be input including BEGIN PRIVATE KEY
    * in the different formats use by OpenSSL, C# and Java Bouncy Castle libraries
    * */
    public String removeTopAndBottomFromPemFile(String pemFile) {
        CharSequence target = "-----BEGIN PRIVATE KEY-----";
        CharSequence replacement = "";
        String pem = pemFile.replace(target, replacement);
        target = "-----BEGIN RSA PRIVATE KEY-----";
        pem = pem.replace(target, replacement);
        target = "-----END RSA PRIVATE KEY-----";
        pem = pem.replace(target, replacement);
        target = "-----END PRIVATE KEY-----";
        pem = pem.replace(target, replacement);
        return pem;
    }
    public String getPrivateKey(BufferedReader bufferedReader)  throws IOException {
        StringBuilder sb = new StringBuilder();
        try {
            String line = bufferedReader.readLine();
            while (line != null) {
                sb.append(line);
                line = bufferedReader.readLine();
            }
        } finally {
            bufferedReader.close();
        }
        return sb.toString();
    }
    /*
    * getPrivateKey: If the private key is saved on the local disc this medthod
    * will read it in and convert it to a string
    * */
    public String getPrivateKey(String pathToPrivateKey_Pem) throws IOException
    {
        StringBuilder sb = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(pathToPrivateKey_Pem));
        try {

            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                line = br.readLine();
            }
        } finally {
            br.close();
        }
        return sb.toString();
    }

}
