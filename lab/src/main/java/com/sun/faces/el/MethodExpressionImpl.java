package com.sun.faces.el;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Stand-in for {@code com.sun.faces.el.MethodExpressionImpl}, the JSF RI's
 * {@code javax.faces.el.MethodExpression} implementation.
 *
 * <p>This is EL site #2 of the two in the serialization stream. The {@code expr} field is
 * raw-UTF written inside a TC_BLOCKDATA segment, matching what the PoC's {@code patch_el()}
 * rewrites. At paint time {@link #getExpressionString()} is what the resource hands to the EL
 * engine, so whatever expression ends up in this field is what gets evaluated.
 */
public class MethodExpressionImpl implements Serializable {

    private static final long serialVersionUID = 4L;

    /** EL text. Raw-UTF written; this is a patch site. */
    private String expr;

    /** Declared expected type of the expression result. */
    private transient Class<?> expectedType;

    /** True when this expression is read-only in JSF terms. */
    private transient boolean readOnly;

    public MethodExpressionImpl(String expr) {
        this.expr = expr;
        this.expectedType = Object.class;
    }

    /** The EL string that gets evaluated during painting. */
    public String getExpressionString() {
        return expr;
    }

    public Class<?> getExpectedType() {
        return expectedType;
    }

    public boolean isReadOnly() {
        return readOnly;
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeUTF(expr);
    }

    private void readObject(ObjectInputStream in) throws IOException {
        expr = in.readUTF();
    }
}
