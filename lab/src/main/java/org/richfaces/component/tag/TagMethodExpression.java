package org.richfaces.component.tag;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import com.sun.faces.el.MethodExpressionImpl;

/**
 * Stand-in for the RichFaces tag-level MethodExpression holder
 * ({@code org.richfaces.component.tag.TagMethodExpression}).
 *
 * <p>This is EL site #1 of the two that appear in the serialization stream. Its {@code attr} is
 * written as a raw modified-UTF string inside a TC_BLOCKDATA segment, which is exactly what the
 * PoC's {@code patch_el()} scans for: it walks the stream looking for
 * {@code 0x77 <segLen> <utfLenHi> <utfLenLo> <utf bytes>} where the string equals the EL the
 * server originally emitted.
 *
 * <p>The class deliberately declares no primitive instance fields. A primitive field would be
 * written into the same block-data segment ahead of the UTF payload, shifting the string off the
 * segment boundary and breaking the two-site contract the PoC depends on.
 *
 * <p>{@code me} is a non-primitive field, so the serialization machinery writes it as an object
 * reference after the block-data segment. That is what pulls {@link MethodExpressionImpl} (EL site
 * #2) into the graph.
 */
public class TagMethodExpression implements Serializable {

    private static final long serialVersionUID = 3L;

    /** The EL expression text. Raw-UTF written; this is a patch site. */
    private String attr;

    /** The delegate JSF actually evaluates. Non-primitive, so it is written as an object reference. */
    private MethodExpressionImpl me;

    /** Escape hatch JSF uses to associate the expression with its owning tag instance. */
    private transient Object owner;

    public TagMethodExpression(String attr) {
        this.attr = attr;
        // The delegate gets its own String instance on purpose.
        //
        // ObjectOutputStream writes each distinct object once and emits a back-reference
        // (TC_REFERENCE) for later occurrences of the same instance. Sharing one String here
        // would therefore collapse both EL sites into a single copy in the stream, and the
        // PoC -- which requires exactly two patch sites -- would reject the blob.
        //
        // Real RichFaces/JSF builds these two expressions from separately parsed strings, so
        // the genuine resource stream does carry the EL twice. new String(...) reproduces that.
        this.me = new MethodExpressionImpl(new String(attr));
    }

    /** The EL text held by this site. */
    public String getAttr() {
        return attr;
    }

    /** The delegate that gets evaluated during painting. */
    public MethodExpressionImpl getMethodExpression() {
        return me;
    }

    public void setOwner(Object owner) {
        this.owner = owner;
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        // Both the attribute EL (site #1) and the delegate (site #2, written by
        // MethodExpressionImpl's own writeObject) go out as raw-UTF block-data segments.
        out.writeUTF(attr);
        out.writeObject(me);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        attr = in.readUTF();
        me = (MethodExpressionImpl) in.readObject();
    }
}
