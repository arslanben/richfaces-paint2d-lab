package lab.rf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * RichFactors transfer encoding used by RichFaces 3.3.x resource URLs
 * ({@code .../a4j/s/3_3_3.Final...Paint2DResource/DATA/<blob>.jsf}).
 *
 * <p>Wire format, outer to inner:
 * <ol>
 *   <li>zlib deflate (RFC 1950) of the payload</li>
 *   <li>standard base64 with a remapped alphabet: {@code + -> -}, {@code / -> !}, {@code = -> _}</li>
 * </ol>
 *
 * <p>The mapping is not a plain alphabet swap in the decode direction: {@code -} decodes to
 * {@code +}, {@code !} decodes to {@code /}, and the pad character {@code _} decodes to
 * {@code =} -- which is why {@link #decode} re-pads with {@code =} afterwards. This mirrors
 * the reference implementation exactly.
 */
public final class RichFactors {

    private RichFactors() {
    }

    /** zlib-compress, then base64 with the RichFaces alphabet. */
    public static String encode(byte[] raw) throws IOException {
        Deflater deflater = new Deflater(Deflater.BEST_SPEED);
        try {
            deflater.setInput(raw);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, raw.length / 2));
            byte[] buf = new byte[4096];
            while (!deflater.finished()) {
                int n = deflater.deflate(buf);
                if (n <= 0) {
                    break;
                }
                out.write(buf, 0, n);
            }
            return remap(base64(out.toByteArray()));
        } finally {
            deflater.end();
        }
    }

    /** Inverse of {@link #encode(byte[])}. */
    public static byte[] decode(String blob) throws IOException {
        String s = blob.trim().replace('!', '/').replace('-', '+').replace('_', '=');
        int pad = (4 - (s.length() % 4)) % 4;
        StringBuilder sb = new StringBuilder(s.length() + pad);
        sb.append(s);
        for (int i = 0; i < pad; i++) {
            sb.append('=');
        }
        byte[] z = unbase64(sb.toString());

        Inflater inflater = new Inflater();
        try {
            inflater.setInput(z);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, z.length * 4));
            byte[] buf = new byte[4096];
            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) {
                        break;
                    }
                } else {
                    out.write(buf, 0, n);
                }
            }
            if (out.size() == 0) {
                throw new IOException("zlib payload inflated to zero bytes");
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException("not a valid RichFactors/zlib payload", e);
        } finally {
            inflater.end();
        }
    }

    private static String remap(String b64) {
        return b64.replace('+', '-').replace('/', '!').replace('=', '_');
    }

    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    private static String base64(byte[] in) {
        StringBuilder sb = new StringBuilder(((in.length + 2) / 3) * 4);
        int i = 0;
        while (i + 2 < in.length) {
            int n = ((in[i] & 0xff) << 16) | ((in[i + 1] & 0xff) << 8) | (in[i + 2] & 0xff);
            sb.append(ALPHABET[(n >>> 18) & 63]).append(ALPHABET[(n >>> 12) & 63])
              .append(ALPHABET[(n >>> 6) & 63]).append(ALPHABET[n & 63]);
            i += 3;
        }
        int rem = in.length - i;
        if (rem == 1) {
            int n = (in[i] & 0xff) << 16;
            sb.append(ALPHABET[(n >>> 18) & 63]).append(ALPHABET[(n >>> 12) & 63]).append("==");
        } else if (rem == 2) {
            int n = ((in[i] & 0xff) << 16) | ((in[i + 1] & 0xff) << 8);
            sb.append(ALPHABET[(n >>> 18) & 63]).append(ALPHABET[(n >>> 12) & 63])
              .append(ALPHABET[(n >>> 6) & 63]).append('=');
        }
        return sb.toString();
    }

    private static byte[] unbase64(String s) throws IOException {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '=') {
            end--;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(end * 3 / 4 + 3);
        int acc = 0;
        int bits = 0;
        for (int i = 0; i < end; i++) {
            int v = value(s.charAt(i));
            if (v < 0) {
                throw new IOException("illegal base64 character: " + s.charAt(i));
            }
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((acc >>> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }

    private static int value(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+' || c == '/') {
            return c == '/' ? 63 : 62;
        }
        return -1;
    }
}
