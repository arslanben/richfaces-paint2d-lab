package lab.web;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CTF layer: awards a flag when a specific exploitation technique is observed.
 *
 * <p>Purely observational -- it reads the expression that reached the EL engine and whatever
 * was already sitting in the session when the request arrived. It never influences
 * exploitability; the vulnerability is fully present with this class removed.
 *
 * <p>The ladder mirrors the real chain:
 * <ol>
 *   <li>{@code flag{el-injection}}  -- a non-default expression reached the EL engine</li>
 *   <li>{@code flag{spel-bootstrap}} -- a SpEL parser was instantiated into the session scope</li>
 *   <li>{@code flag{rce-confirmed}}  -- a stored SpEL expression was evaluated and it ran a process</li>
 *   <li>{@code flag{rce-file-read}}  -- a stored SpEL expression was evaluated and it read a file</li>
 * </ol>
 *
 * <p><b>Ordering matters.</b> This must be called <em>before</em> the EL is evaluated, not after.
 * The chain is spread over three requests, and by the time the EL that stores a parsed
 * expression has run, the session already holds it -- so classifying after evaluation would let
 * {@code parseExpression("1+1")}, which executes nothing, be scored as confirmed code execution.
 */
public class FlagService {

    /**
     * The expression the server legitimately embeds in the captcha blob.
     *
     * <p>Public so the servlets can reference a single definition. It must stay byte-stable,
     * because the PoC searches the serialized stream for exactly this text.
     */
    public static final String DEFAULT_EL = "#{userLoginController.paintCaptcha}";

    private static final Map<String, String> FLAGS = new LinkedHashMap<>();

    /** level -> flag, so classification is a single lookup rather than a scan. */
    private static final Map<String, String> BY_LEVEL = new LinkedHashMap<>();

    static {
        FLAGS.put("flag{el-injection}", "1");
        FLAGS.put("flag{spel-bootstrap}", "2");
        FLAGS.put("flag{rce-confirmed}", "3");
        FLAGS.put("flag{rce-file-read}", "4");
        for (Map.Entry<String, String> e : FLAGS.entrySet()) {
            BY_LEVEL.put(e.getValue(), e.getKey());
        }
    }

    /**
     * Classifies one request.
     *
     * @param expression the expression that reached the EL engine, or {@code null}/empty when the
     *                   payload carried none
     * @param session    the session scope map as it stood <em>before</em> this request's EL ran
     * @return the flag earned, or {@code ""} for the unmodified default expression
     */
    public String observe(String expression, Map<String, Object> session) {
        if (expression == null || expression.isEmpty() || DEFAULT_EL.equals(expression)) {
            return "";
        }

        // Judge the request by the primitive it executes, not by the text it carries.
        //
        // The SpEL payload travels as an EL string literal, so the file-read or command text is
        // quoted rather than executed by the request that stores it. Blank the literals before
        // matching, otherwise "this request plans to read a file" is indistinguishable from
        // "this request read a file".
        String body = stripStringLiterals(expression);

        boolean evaluates = body.contains(".getValue()");
        boolean bootstraps = mentions(body,
                "SpelExpressionParser", "forName", "getClass()", "newInstance");
        boolean prepares = body.contains("parseExpression");

        // A parsed SpEL expression exposes its own source, so the evaluate request can be judged
        // by what it actually ran.
        String stored = firstStoredSpelSource(session);

        String level;
        if (evaluates && stored != null) {
            // This request really did evaluate a stored expression, so it can be judged by what
            // that expression does. Evaluating something harmless like "1+1" is not RCE, so it
            // must not collect the execution rung.
            if (mentions(stored, "FileInputStream", "FileReader", "Files.", "Scanner")) {
                level = "4";
            } else if (mentions(stored, "Runtime", "ProcessBuilder", "exec(")) {
                level = "3";
            } else {
                level = "2";
            }
        } else if (bootstraps) {
            level = "2";
        } else if (prepares) {
            // parseExpression runs nothing; it only stores code for a later request.
            level = "2";
        } else {
            level = "1";
        }

        return BY_LEVEL.getOrDefault(level, "");
    }

    private static boolean mentions(String s, String... needles) {
        for (String n : needles) {
            if (s.contains(n)) {
                return true;
            }
        }
        return false;
    }

    /** Source text of the first stored SpEL expression, or null if the session holds none. */
    private static String firstStoredSpelSource(Map<String, Object> session) {
        for (Object o : session.values()) {
            try {
                java.lang.reflect.Method m = o.getClass().getMethod("getExpressionString");
                Object v = m.invoke(o);
                if (v instanceof String) {
                    return (String) v;
                }
            } catch (ReflectiveOperationException | RuntimeException ignored) {
                // not a SpEL expression; keep looking
            }
        }
        return null;
    }

    /** Replaces the contents of double-quoted literals with spaces, preserving offsets. */
    private static String stripStringLiterals(String expr) {
        StringBuilder out = new StringBuilder(expr.length());
        boolean inString = false;
        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);
            if (inString && c == '\\' && i + 1 < expr.length()) {
                out.append(c).append(expr.charAt(++i));
                continue;
            }
            if (c == '"') {
                inString = !inString;
                out.append(c);
                continue;
            }
            out.append(inString ? ' ' : c);
        }
        return out.toString();
    }

    /** All flags, for the lab's hints endpoint. */
    public static Map<String, String> all() {
        return FLAGS;
    }
}
