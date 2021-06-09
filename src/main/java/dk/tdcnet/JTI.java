package dk.tdcnet;

import java.security.SecureRandom;
import java.util.Random;

public class JTI {
    /**
     * Generate a random string to be used in the JTI claim.
     * JTI is the unique JWT id claim
     * It must be unique and can only be used once.
     */
    public String nextRandomString() {
        for (int idx = 0; idx < buf.length; ++idx)
            buf[idx] = symbols[random.nextInt(symbols.length)];
        return new String(buf);
    }

    public static final String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static final String lower = upper.toLowerCase();

    public static final String digits = "0123456789";

    public static final String alphanum = upper + lower + digits;

    private static Random random;

    private static char[] symbols;

    private static char[] buf;

    public JTI(int length, Random random, String symbols) {
        if (length < 1) throw new IllegalArgumentException();
        if (symbols.length() < 2) throw new IllegalArgumentException();
        if (random != null) {
            this.random = random;
            this.symbols = symbols.toCharArray();
            this.buf = new char[length];
        }
    }

    /**
     * Create an alphanumeric string generator.
     */
    public JTI(int length, Random random) {
        this(length, random, alphanum);
    }

    /**
     * Create an alphanumeric strings from a secure generator.
     */
    public JTI(int length) {
        this(length, new SecureRandom());
    }

    /**
     * Create session identifiers.
     */
    public JTI() {
        this(21);
    }

}
