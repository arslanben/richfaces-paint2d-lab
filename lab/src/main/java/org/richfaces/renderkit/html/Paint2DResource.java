package org.richfaces.renderkit.html;

import java.io.Serializable;

import javax.faces.component.StateHolderSaver;

/**
 * Stand-in for the captcha payload carried by RichFaces'
 * {@code org.richfaces.renderkit.html.Paint2DResource}.
 *
 * <p>This is the root object of the deserialization graph:
 *
 * <pre>
 *   Paint2DResource$ImageData
 *     └─ StateHolderSaver
 *          └─ { "value": TagMethodExpression -&gt; MethodExpressionImpl }
 * </pre>
 *
 * <p>Two independent EL sites sit under it, both originally holding the same expression string:
 * {@code TagMethodExpression.attr} and {@code MethodExpressionImpl.expr}. Patching both is exactly
 * what the PoC's {@code patch_el()} does, which is why it insists on finding two sites.
 *
 * <p>{@code width}, {@code height} and {@code noise} are emitted by default serialization into this
 * class's own block-data segment, ahead of the nested objects. Their leading bytes never form a
 * self-consistent UTF length, so the PoC's scan skips them.
 */
public class Paint2DResource implements Serializable {

    private static final long serialVersionUID = 5L;

    /** Serializable payload describing one captcha render. */
    public static class ImageData implements Serializable {

        private static final long serialVersionUID = 6L;

        /** Rendered captcha width in pixels. */
        private int width;

        /** Rendered captcha height in pixels. */
        private int height;

        /** Opaque render salt; keeps consecutive captchas visually distinct. */
        private int noise;

        /** Saved JSF state; the EL-bearing entry lives inside. */
        private Object state;

        public ImageData(int width, int height, int noise, StateHolderSaver state) {
            this.width = width;
            this.height = height;
            this.noise = noise;
            this.state = state;
        }

        public int getWidth() {
            return width;
        }

        public int getHeight() {
            return height;
        }

        public int getNoise() {
            return noise;
        }

        /** The restored state holder, or null if the stream did not carry one. */
        public StateHolderSaver getState() {
            return state instanceof StateHolderSaver ? (StateHolderSaver) state : null;
        }
    }
}
