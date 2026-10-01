package lab.web;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import lab.faces.ElEngine;
import lab.faces.FacesContextAdapter;
import lab.rf.RichFactors;

import org.richfaces.renderkit.html.Paint2DResource;

/**
 * The vulnerable resource endpoint.
 *
 * <p>Handles {@code /a4j/s/3_3_3.Finalorg.richfaces.renderkit.html.Paint2DResource/DATA/<blob>.jsf}
 * and does, in order, exactly what the original did:
 *
 * <ol>
 *   <li>RichFactors-decode the URL blob (base64 variant + zlib inflate)</li>
 *   <li>Java-deserialize the payload into {@code Paint2DResource$ImageData}</li>
 *   <li>walk the restored state to the MethodExpression and evaluate its EL string</li>
 *   <li>paint the captcha JPEG, after flushing any headers the EL set</li>
 * </ol>
 *
 * <p>Step 3 is the vulnerability (CVE-2018-12533): the EL text comes from the client-supplied
 * blob, so whoever can craft the blob chooses what gets evaluated. The absence of any integrity
 * check on the blob <em>is</em> the bug.
 */
public class Paint2DResourceServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** Session attribute under which the JSF-style scope map is stored. */
    static final String SESSION_SCOPES = "scopes";

    /**
     * The EL the server legitimately ships inside the captcha blob.
     *
     * <p>Fixed on purpose: the PoC's {@code patch_el()} searches for exactly this string, so it
     * must never vary between requests.
     */
    public static final String DEFAULT_EL = FlagService.DEFAULT_EL;

    private final transient ElEngine el = new ElEngine();
    private final transient FlagService flags = new FlagService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String blob = extractBlob(req);
        if (blob == null || blob.isEmpty()) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "missing Paint2DResource data");
            return;
        }

        byte[] stream;
        try {
            stream = RichFactors.decode(blob);
        } catch (IOException e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "malformed resource payload");
            return;
        }

        Paint2DResource.ImageData image;
        try {
            image = deserialize(stream);
        } catch (Exception e) {
            // RichFaces would bounce back to the view here. The PoC treats a non-image
            // content type as a failed paint, so keep it a hard error.
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "state restore failed");
            return;
        }

        String expression = resolveExpression(image);
        Map<String, Object> session = sessionMap(req);

        FacesContextAdapter fc = new FacesContextAdapter(session);
        Map<String, Object> implicit = ElEngine.scopes(fc, session);

        // Score the request BEFORE the EL runs.
        //
        // The SpEL chain takes three requests and the session accumulates across them. If this
        // were called afterwards, the request that stores a parsed expression would already find
        // it in the session and get credited with executing it.
        String flag = flags.observe(expression, new HashMap<>(session));

        String elError = null;
        if (expression != null) {
            // EL runs on the thread that serves the request, so its context classloader is the
            // webapp loader. Reflective lookups performed from EL (e.g. String#forName resolving
            // application libraries) resolve against that loader. Pinning it explicitly keeps the
            // behaviour identical no matter which thread Tomcat dispatches the paint onto.
            ClassLoader previous = Thread.currentThread().getContextClassLoader();
            Thread.currentThread().setContextClassLoader(Paint2DResourceServlet.class.getClassLoader());
            try {
                el.evaluate(expression, implicit);
            } catch (Throwable t) {
                // Painting continues: the EL is attacker input and is expected to throw
                // sometimes. Report it as a header so the lab stays debuggable without
                // changing the response contract.
                elError = t.getClass().getSimpleName() + ": " + t.getMessage();
            } finally {
                Thread.currentThread().setContextClassLoader(previous);
            }
        }

        byte[] jpeg = paint(image);

        if (elError != null) {
            fc.setHeader("X-Lab-ElError", elError);
        }
        fc.setHeader("X-Lab-Flag", flag);
        fc.flushInto(resp);

        resp.setContentType("image/jpeg");
        resp.setContentLength(jpeg.length);
        resp.getOutputStream().write(jpeg);
    }

    /** Pulls the blob out of the resource path. */
    private static String extractBlob(HttpServletRequest req) {
        String uri = req.getRequestURI();
        String ctx = req.getContextPath();
        String path = uri.substring(Math.min(ctx.length(), uri.length()));

        int marker = path.indexOf("/DATA/");
        if (marker < 0) {
            return null;
        }
        String tail = path.substring(marker + "/DATA/".length());
        if (tail.endsWith(".jsf")) {
            tail = tail.substring(0, tail.length() - ".jsf".length());
        }
        return tail;
    }

    /**
     * Java-deserializes the attacker-supplied payload.
     *
     * <p>Plain {@code ObjectInputStream}, no filter, on purpose: the original endpoint
     * deserialized client-supplied state without validation, and reproducing that behaviour is
     * the point of the lab.
     */
    private static Paint2DResource.ImageData deserialize(byte[] stream) throws Exception {
        try (InputStream in = new ByteArrayInputStream(stream);
             ObjectInputStream ois = new ObjectInputStream(in)) {
            Object o = ois.readObject();
            if (o instanceof Paint2DResource.ImageData) {
                return (Paint2DResource.ImageData) o;
            }
            throw new IOException("unexpected payload type: " + o);
        }
    }

    /**
     * Walks the restored state down to the MethodExpression and returns the EL string that JSF
     * would evaluate while painting.
     */
    private static String resolveExpression(Paint2DResource.ImageData image) {
        javax.faces.component.StateHolderSaver state = image.getState();
        if (state == null) {
            return null;
        }
        Object me = state.getMethodExpression();
        if (me instanceof org.richfaces.component.tag.TagMethodExpression) {
            org.richfaces.component.tag.TagMethodExpression tme =
                    (org.richfaces.component.tag.TagMethodExpression) me;
            com.sun.faces.el.MethodExpressionImpl delegate = tme.getMethodExpression();
            return delegate != null ? delegate.getExpressionString() : tme.getAttr();
        }
        return null;
    }

    /** Renders the captcha image so the endpoint returns a real image/jpeg body. */
    private static byte[] paint(Paint2DResource.ImageData image) throws IOException {
        int w = Math.max(60, Math.min(400, image.getWidth()));
        int h = Math.max(30, Math.min(200, image.getHeight()));
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(new Color(245, 245, 248));
            g.fillRect(0, 0, w, h);

            Random rnd = new Random(image.getNoise());
            for (int i = 0; i < 24; i++) {
                g.setColor(new Color(rnd.nextInt(0xFFFFFF)));
                int x = rnd.nextInt(Math.max(1, w));
                int y = rnd.nextInt(Math.max(1, h));
                g.drawLine(x, y, x + rnd.nextInt(9) - 4, y + rnd.nextInt(9) - 4);
            }
            g.setColor(new Color(30, 30, 90));
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, Math.max(11, h / 3)));
            g.drawString(String.format("%04d", Math.abs(image.getNoise()) % 10000), 8, h / 2 + 5);
        } finally {
            g.dispose();
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ImageIO.write(img, "jpeg", bos);
        return bos.toByteArray();
    }

    /**
     * The HTTP session exposed as a plain mutable map, because the EL chain stores arbitrary
     * objects in it (a {@code SpelExpressionParser}, a parsed {@code Expression}) between the
     * three separate paint requests the PoC makes.
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> sessionMap(HttpServletRequest req) {
        HttpSession session = req.getSession(true);
        synchronized (session) {
            Object existing = session.getAttribute(SESSION_SCOPES);
            if (existing instanceof Map) {
                return (Map<String, Object>) existing;
            }
            Map<String, Object> scopes = new HashMap<>();
            session.setAttribute(SESSION_SCOPES, scopes);
            return scopes;
        }
    }
}
