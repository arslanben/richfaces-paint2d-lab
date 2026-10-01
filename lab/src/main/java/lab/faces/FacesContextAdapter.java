package lab.faces;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal stand-in for the JSF {@code FacesContext} object graph.
 *
 * <p>Only the surface the PoC touches is modelled:
 *
 * <pre>
 *   #{facesContext.getExternalContext().getResponse().setHeader("X-Out", ...)}
 *   #{facesContext.getExternalContext().sessionMap.put("p", ...)}
 * </pre>
 *
 * <p>{@link #setHeader} records headers instead of writing them straight to the socket. That is
 * deliberate and mirrors how the original exploit worked: the EL runs while the image is being
 * painted, so headers have to be collected and flushed onto the response before the JPEG body is
 * committed. It also lets the lab award CTF flags for specific technique milestones.
 */
public class FacesContextAdapter {

    /** Header name -> values, in insertion order, case-insensitive on lookup. */
    private final Map<String, java.util.List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    /** The backing session map (mutable: the PoC stores objects here between requests). */
    private final Map<String, Object> session;

    private final ExternalContextAdapter externalContext;

    public FacesContextAdapter(Map<String, Object> session) {
        this.session = session;
        this.externalContext = new ExternalContextAdapter(this, session);
    }

    public ExternalContextAdapter getExternalContext() {
        return externalContext;
    }

    public Map<String, Object> getSessionMap() {
        return session;
    }

    public void setHeader(String name, String value) {
        java.util.List<String> values = headers.computeIfAbsent(name, k -> new java.util.ArrayList<>());
        values.clear();
        values.add(value);
    }

    public void addHeader(String name, String value) {
        headers.computeIfAbsent(name, k -> new java.util.ArrayList<>()).add(value);
    }

    public String getHeader(String name) {
        java.util.List<String> values = headers.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    /** All headers set during this paint, ready to be flushed onto the real response. */
    public Map<String, java.util.List<String>> getHeaders() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    public void flushInto(javax.servlet.http.HttpServletResponse response) {
        for (Map.Entry<String, java.util.List<String>> e : headers.entrySet()) {
            for (String v : e.getValue()) {
                response.addHeader(e.getKey(), v);
            }
        }
    }

    /** {@code ExternalContext} surface: response handle plus scope maps. */
    public static class ExternalContextAdapter {

        private final FacesContextAdapter faces;
        private final Map<String, Object> session;

        ExternalContextAdapter(FacesContextAdapter faces, Map<String, Object> session) {
            this.faces = faces;
            this.session = session;
        }

        public FacesContextAdapter getResponse() {
            return faces;
        }

        public Map<String, Object> getSessionMap() {
            return session;
        }

        public Object getSession(String key) {
            return session.get(key);
        }

        public void setSession(String key, Object value) {
            session.put(key, value);
        }
    }
}
