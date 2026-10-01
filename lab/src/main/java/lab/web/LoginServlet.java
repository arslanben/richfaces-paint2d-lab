package lab.web;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lab.rf.RichFactors;

import org.richfaces.renderkit.html.Paint2DResource;

import com.sun.faces.el.MethodExpressionImpl;

import javax.faces.component.StateHolderSaver;

import org.richfaces.component.tag.TagMethodExpression;

/**
 * The login page. Emits the captcha {@code <img>} whose {@code src} carries the RichFactors
 * blob, which is exactly where the PoC starts harvesting.
 *
 * <p>The important detail for reproducibility: the expression string written into the blob is
 * always the fixed {@link Paint2DResourceServlet#DEFAULT_EL}, so the PoC's
 * {@code patch_el()} always finds the same two sites.
 */
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** Path prefix the PoC hardcodes when replaying the captcha resource. */
    public static final String RESOURCE_PREFIX = "/a4j/s/3_3_3.Finalorg.richfaces.renderkit.html.Paint2DResource";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // Create the session up front so the JSESSIONID cookie is issued with the page itself.
        // The PoC replays three separate requests against the captcha resource and relies on
        // them sharing one session (the SpEL parser is stashed in step 1, read back in step 3),
        // so the cookie has to be established here rather than on the first paint.
        Paint2DResourceServlet.sessionMap(req);

        String el = Paint2DResourceServlet.DEFAULT_EL;
        String blob;
        try {
            blob = buildBlob(el);
        } catch (IOException e) {
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "captcha build failed");
            return;
        }

        String ctx = req.getContextPath();
        String captchaUrl = ctx + RESOURCE_PREFIX + "/DATA/" + blob + ".jsf";
        String postUrl = ctx + "/pages/topup.jsf";

        resp.setContentType("text/html;charset=UTF-8");
        resp.getWriter().write(html(captchaUrl, postUrl));
    }

    /**
     * Builds the serialized captcha state and RichFactors-encodes it.
     *
     * <p>The graph mirrors the reference report:
     * {@code ImageData -> StateHolderSaver -> {value: TagMethodExpression -> MethodExpressionImpl}},
     * with the same EL written into both expression holders.
     */
    private static String buildBlob(String el) throws IOException {
        TagMethodExpression tme = new TagMethodExpression(el);

        Map<String, Object> stateMap = new HashMap<>();
        stateMap.put(StateHolderSaver.KEY_METHOD_EXPRESSION, tme);

        StateHolderSaver saver = new StateHolderSaver(Paint2DResource.ImageData.class, stateMap);
        Paint2DResource.ImageData data =
                new Paint2DResource.ImageData(180, 60, (int) (System.nanoTime() & 0x7fffffff), saver);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(data);
        }
        return RichFactors.encode(bos.toByteArray());
    }

    private static String html(String captchaUrl, String postUrl) {
        return "<!DOCTYPE html>\n"
             + "<html lang=\"en\">\n"
             + "<head><meta charset=\"utf-8\"><title>TopUp :: Login</title>\n"
             + "<style>body{font-family:system-ui,sans-serif;margin:0;background:#f4f6fa;color:#1c2333}"
             + ".card{max-width:380px;margin:60px auto;background:#fff;padding:28px 32px;border-radius:10px;"
             + "box-shadow:0 2px 12px rgba(20,30,60,.08)}"
             + "h1{font-size:19px;margin:0 0 4px}.sub{color:#667;font-size:13px;margin:0 0 22px}"
             + "label{display:block;font-size:12px;margin:14px 0 5px;color:#445}"
             + "input{width:100%;box-sizing:border-box;padding:9px 11px;border:1px solid #ccd3e0;"
             + "border-radius:6px;font-size:14px}"
             + "img{border:1px solid #ccd3e0;border-radius:6px;margin-top:8px}"
             + "button{margin-top:20px;width:100%;padding:10px;background:#1d4ed8;color:#fff;"
             + "border:0;border-radius:6px;font-size:14px;cursor:pointer}"
             + "</style></head>\n"
             + "<body><div class=\"card\">\n"
             + "<h1>TopUp Console</h1>\n"
             + "<p class=\"sub\">Sign in to manage subscriber top-ups.</p>\n"
             + "<form method=\"post\" action=\"" + postUrl + "\">\n"
             + "<label for=\"u\">Username</label><input id=\"u\" name=\"username\">\n"
             + "<label for=\"p\">Password</label><input id=\"p\" name=\"password\" type=\"password\">\n"
             + "<label>Captcha</label><img id=\"captcha\" alt=\"captcha\" src=\"" + captchaUrl + "\">\n"
             + "<input type=\"hidden\" name=\"captchaField\" value=\"\">\n"
             + "<button type=\"submit\">Sign in</button>\n"
             + "</form>\n"
             + "</div></body></html>\n";
    }
}
