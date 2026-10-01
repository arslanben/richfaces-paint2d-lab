package javax.faces.component;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Stand-in for {@code javax.faces.component.StateHolderSaver}.
 *
 * <p>In JSF a component's saved state can be captured by pairing the component instance with a
 * name/value map. In this lab it provides the middle link of the gadget chain:
 *
 * <pre>
 *   Paint2DResource$ImageData -&gt; StateHolderSaver -&gt; {map} -&gt; TagMethodExpression -&gt; MethodExpressionImpl
 * </pre>
 *
 * <p>The class name matters: it is written verbatim into the Java serialization stream, so it is
 * visible to anybody who decodes the resource blob. This class intentionally declares no primitive
 * fields and uses default serialization, so it contributes no raw-UTF block to the stream and the
 * EL sites stay limited to the two MethodExpression holders.
 */
public class StateHolderSaver implements Serializable {

    private static final long serialVersionUID = 2L;

    /** Component class this state belongs to. */
    private Class<?> classToRestore;

    /** name -&gt; value map; the EL-bearing entry is stored under {@link #KEY_METHOD_EXPRESSION}. */
    private Map<String, Object> state;

    public static final String KEY_METHOD_EXPRESSION = "value";

    public StateHolderSaver(Class<?> classToRestore, Map<String, Object> state) {
        this.classToRestore = classToRestore;
        this.state = state == null ? new HashMap<>() : state;
    }

    public Class<?> getClassToRestore() {
        return classToRestore;
    }

    public Map<String, Object> getState() {
        return state;
    }

    /** The deserialized expression object that JSF would evaluate while painting. */
    public Object getMethodExpression() {
        return state == null ? null : state.get(KEY_METHOD_EXPRESSION);
    }
}
