package lab.faces;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import javax.el.BeanELResolver;
import javax.el.CompositeELResolver;
import javax.el.ELContext;
import javax.el.ELResolver;
import javax.el.ExpressionFactory;
import javax.el.ListELResolver;
import javax.el.MapELResolver;
import javax.el.ArrayELResolver;
import javax.el.StaticFieldELResolver;
import javax.el.ValueExpression;

/**
 * The sink: evaluates an EL string against a JSF-shaped object graph.
 *
 * <p>This mirrors what the JSF runtime does when a component evaluates a MethodExpression, and it
 * is where the CVE-2018-12533 chain actually executes attacker-controlled code. The implicit
 * objects exposed here are the ones the PoC relies on:
 *
 * <ul>
 *   <li>{@code facesContext.getExternalContext().getResponse().setHeader(name, value)}</li>
 *   <li>{@code facesContext.getExternalContext().sessionMap.put(key, value)}</li>
 *   <li>{@code sessionScope[key]}</li>
 * </ul>
 */
public final class ElEngine {

    private final ExpressionFactory ef = ExpressionFactory.newInstance();

    /**
     * Resolves bare identifiers ({@code facesContext}, {@code sessionScope}, ...) and delegates
     * everything else down the chain.
     */
    private static final class ImplicitObjectResolver extends ELResolver {

        private final Map<String, Object> vars;

        ImplicitObjectResolver(Map<String, Object> vars) {
            this.vars = vars;
        }

        @Override
        public Object getValue(ELContext ctx, Object base, Object property) {
            if (base == null && property != null && vars.containsKey(property)) {
                ctx.setPropertyResolved(true);
                return vars.get(property);
            }
            return null;
        }

        @Override
        public Class<?> getType(ELContext ctx, Object base, Object property) {
            if (base == null && property != null && vars.containsKey(property)) {
                ctx.setPropertyResolved(true);
                Object v = vars.get(property);
                return v == null ? null : v.getClass();
            }
            return null;
        }

        @Override
        public void setValue(ELContext ctx, Object base, Object property, Object value) {
            if (base == null && property != null && vars.containsKey(property)) {
                ctx.setPropertyResolved(true);
                vars.put(String.valueOf(property), value);
            }
        }

        @Override
        public boolean isReadOnly(ELContext ctx, Object base, Object property) {
            return false;
        }

        @Override
        public java.util.Iterator<java.beans.FeatureDescriptor> getFeatureDescriptors(
                ELContext ctx, Object base) {
            return null;
        }

        @Override
        public Class<?> getCommonPropertyType(ELContext ctx, Object base) {
            return base == null ? String.class : null;
        }
    }

    /**
     * Evaluates {@code expr} with the supplied implicit objects in scope.
     *
     * @return whatever the expression evaluates to; the PoC mostly cares about side effects
     *         (headers set, session entries created) rather than the return value.
     */
    public Object evaluate(String expr, Map<String, Object> implicitObjects) {
        CompositeELResolver chain = new CompositeELResolver();
        chain.add(new ImplicitObjectResolver(implicitObjects));
        chain.add(new MapELResolver());
        chain.add(new ListELResolver());
        chain.add(new ArrayELResolver());
        chain.add(new BeanELResolver());
        chain.add(new StaticFieldELResolver());

        ELContext ctx = new ELContext() {
            @Override
            public ELResolver getELResolver() {
                return chain;
            }

            @Override
            public javax.el.FunctionMapper getFunctionMapper() {
                return new javax.el.FunctionMapper() {
                    @Override
                    public Method resolveFunction(String prefix, String local) {
                        return null;
                    }
                };
            }

            @Override
            public javax.el.VariableMapper getVariableMapper() {
                return null;
            }
        };

        ValueExpression ve = ef.createValueExpression(ctx, expr, Object.class);
        return ve.getValue(ctx);
    }

    /** Convenience: a fresh implicit-object map seeded with the four JSF scope objects. */
    public static Map<String, Object> scopes(FacesContextAdapter fc, Map<String, Object> session) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("facesContext", fc);
        vars.put("sessionScope", session);
        vars.put("requestScope", new HashMap<String, Object>());
        vars.put("applicationScope", new HashMap<String, Object>());
        return vars;
    }
}
