package lab.web;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Lab-only surface: hints, the flag list, and a health probe.
 *
 * <p>Kept separate from the vulnerable code path so participants can read the intended
 * technique list before starting, and so CI can assert the lab is up without touching the sink.
 */
public class LabServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getPathInfo() == null ? "/" : req.getPathInfo();

        switch (path) {
            case "/health":
                resp.setContentType("application/json");
                resp.getWriter().write("{\"status\":\"ok\",\"vulnerable\":\"CVE-2018-12533\"}");
                return;
            case "/flags":
                resp.setContentType("application/json");
                resp.getWriter().write("{\"flags\":["
                        + "\"flag{el-injection}\","
                        + "\"flag{spel-bootstrap}\","
                        + "\"flag{rce-confirmed}\","
                        + "\"flag{rce-file-read}\"]}");
                return;
            case "/hints":
            case "/":
                resp.setContentType("text/html;charset=UTF-8");
                resp.getWriter().write(hints(req.getContextPath()));
                return;
            default:
                resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    private static String hints(String ctx) {
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
             + "<title>Lab notes</title>"
             + "<style>body{font-family:system-ui,sans-serif;background:#f4f6fa;color:#1c2333;"
             + "margin:0;padding:40px 24px}.card{max-width:760px;margin:0 auto;background:#fff;"
             + "padding:32px;border-radius:10px;box-shadow:0 2px 12px rgba(20,30,60,.08)}"
             + "h1{font-size:20px;margin:0 0 6px}.sub{color:#667;font-size:14px;margin:0 0 24px}"
             + "h2{font-size:15px;margin:26px 0 8px}code,pre{background:#f1f4fa;border-radius:5px;"
             + "padding:2px 6px;font-size:13px}pre{padding:12px 14px;overflow:auto}"
             + "li{margin:6px 0;font-size:14px;line-height:1.55}.warn{background:#fff7ed;"
             + "border-left:3px solid #f59e0b;padding:12px 14px;font-size:13px;margin:0 0 22px}"
             + "</style></head><body><div class=\"card\">"
             + "<h1>RichFaces Paint2DResource lab</h1>"
             + "<p class=\"sub\">CVE-2018-12533 &mdash; EL injection in the captcha resource</p>"
             + "<div class=\"warn\"><strong>Lab only.</strong> This application is intentionally "
             + "vulnerable and deserializes untrusted state. Never run it on a reachable network."
             + "</div>"
             + "<h2>Where to look</h2>"
             + "<ul>"
             + "<li><code>GET /pages/login.jsf</code> returns a captcha "
             + "<code>&lt;img&gt;</code> whose <code>src</code> embeds a RichFactors blob.</li>"
             + "<li>The blob is <code>zlib(base64(...))</code> over a Java serialization stream "
             + "containing a <code>Paint2DResource$ImageData</code> graph.</li>"
             + "<li>Requesting that resource back makes the server evaluate the "
             + "<code>MethodExpression</code> EL found inside it.</li>"
             + "</ul>"
             + "<h2>Technique ladder</h2>"
             + "<ul>"
             + "<li><strong>1. Decode.</strong> Reverse the RichFactors encoding and inspect the "
             + "stream (<code>ac ed 00 05</code> is the Java serialization magic).</li>"
             + "<li><strong>2. Patch.</strong> Two copies of the EL live in "
             + "<code>TC_BLOCKDATA</code> segments. Replace both and fix the segment length "
             + "prefixes.</li>"
             + "<li><strong>3. Inject.</strong> Write an arbitrary response header from EL alone "
             + "&rarr; <code>flag{el-injection}</code>.</li>"
             + "<li><strong>4. Escalate.</strong> Put a SpEL parser in the session scope, then a "
             + "parsed expression &rarr; <code>flag{spel-bootstrap}</code>.</li>"
             + "<li><strong>5. Execute.</strong> Evaluate it to run a command and return the "
             + "output &rarr; <code>flag{rce-confirmed}</code>.</li>"
             + "<li><strong>6. Read.</strong> Use the same primitive on a file instead of a "
             + "process &rarr; <code>flag{rce-file-read}</code>.</li>"
             + "</ul>"
             + "<h2>Environment</h2>"
             + "<ul>"
             + "<li>App user: <code>labuser</code> (uid 1003), matching the account id "
             + "reported in the original disclosure.</li>"
             + "<li>The webapp is deployed under <code>" + ctx + "</code>, so every path "
             + "carries that prefix.</li>"
             + "<li><code>spring-expression</code> sits next to the EL engine in the shared "
             + "class realm, which is what makes the SpEL step reachable.</li>"
             + "</ul>"
             + "<p style=\"margin-top:26px\"><a href=\"" + ctx + "/lab/health\">"
             + ctx + "/lab/health</a> &middot; "
             + "<a href=\"" + ctx + "/lab/flags\">" + ctx + "/lab/flags</a> &middot; "
             + "<a href=\"" + ctx + "/pages/login.jsf\">" + ctx + "/pages/login.jsf</a></p>"
             + "</div></body></html>";
    }
}
