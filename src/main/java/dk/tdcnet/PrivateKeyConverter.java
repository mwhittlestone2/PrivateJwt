package dk.tdcnet;

//import com.fasterxml.jackson.databind.util.ClassUtil;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;
import java.io.Reader;
import java.security.PrivateKey;

import java.io.FileReader;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
//import org.bouncycastle.util.io.pem.PemReader;


public class PrivateKeyConverter {

    public PrivateKeyConverter() {
        //Constructor
    }
    //PEMParser reader = null; //DEPRECATED
    //PEMParser parser = null;
    public PrivateKey ReadPEM(Reader reader) {
        //PEMParser pp = new PEMParser(reader);
        PEMParser parser = null;
        PrivateKey privateKeyJava = null;
        try {
            parser = new PEMParser(reader);
            PrivateKeyInfo info = null;

            // the return type depends on whether the file contains a single key or a key pair
            Object bouncyCastleResult = parser.readObject();

            if (bouncyCastleResult instanceof PrivateKeyInfo) {
                info = (PrivateKeyInfo) bouncyCastleResult;
            } else if (bouncyCastleResult instanceof PEMKeyPair) {
                PEMKeyPair keys = (PEMKeyPair) bouncyCastleResult;
                info = keys.getPrivateKeyInfo();
            } else {
                throw new Exception("No private key found in the provided file");
            }

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            privateKeyJava = converter.getPrivateKey(info);
            //privateKeyJava = ReadString(info);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                }
            }

        }
        return privateKeyJava;
    }

        public PrivateKey ReadPEM(String fileName) {
            PrivateKey privateKeyJava = null;
            PEMParser parser = null;
            try {

                parser = new PEMParser(new FileReader(fileName));

                PrivateKeyInfo info = null;

                // the return type depends on whether the file contains a single key or a key pair
                Object bouncyCastleResult = parser.readObject();

                if (bouncyCastleResult instanceof PrivateKeyInfo) {
                    info = (PrivateKeyInfo) bouncyCastleResult;
                } else if (bouncyCastleResult instanceof PEMKeyPair) {
                    PEMKeyPair keys = (PEMKeyPair) bouncyCastleResult;
                    info = keys.getPrivateKeyInfo();
                } else {
                    throw new Exception("No private key found in the provided file");
                }

                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

                privateKeyJava = converter.getPrivateKey(info);
                //privateKeyJava = ReadString(info);

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (parser != null) {
                    try {
                        parser.close();
                    } catch (IOException e) {
                    }
                }

            }
            return privateKeyJava;
        }


        public byte[] toPkcs8(PrivateKey k) throws IOException {
            final String keyFormat = k.getFormat();

            if (keyFormat.equals("PKCS#8")) {
                return k.getEncoded();
            } else if (keyFormat.equals("PKCS#1")) {
                try {
                    ASN1InputStream asn1InputStream = new ASN1InputStream(k.getEncoded());
                    ASN1Primitive rsaPrivateKey = asn1InputStream.readObject();
                    return new PrivateKeyInfo(
                            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), rsaPrivateKey)
                            .getEncoded("DER");
                } catch (Exception e) {
                    System.out.println("Exception " + e.getMessage());
                    throw new IOException("Unexpected key format" + keyFormat);
                }
            }
            return null;
        }

}
