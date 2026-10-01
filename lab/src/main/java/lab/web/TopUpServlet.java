package lab.web;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** Landing page after a (fake) login. Exists so the app shape looks like a real JSF application. */
public class TopUpServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html;charset=UTF-8");
        resp.getWriter().write("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<title>TopUp :: Dashboard</title>"
                + "<style>body{font-family:system-ui,sans-serif;background:#f4f6fa;color:#1c2333;"
                + "margin:0}.card{max-width:520px;margin:60px auto;background:#fff;padding:28px 32px;"
                + "border-radius:10px;box-shadow:0 2px 12px rgba(20,30,60,.08)}"
                + "h1{font-size:19px;margin:0 0 16px}table{width:100%;border-collapse:collapse}"
                + "td,th{text-align:left;padding:8px 4px;border-bottom:1px solid #e6eaf2;font-size:14px}"
                + "th{color:#667;font-weight:600;font-size:12px}</style></head><body><div class=\"card\">"
                + "<h1>Top-up dashboard</h1>"
                + "<table><tr><th>MSISDN</th><th>Amount</th><th>Status</th></tr>"
                + "<tr><td>+90 555 000 00 01</td><td>50.00 TL</td><td>Completed</td></tr>"
                + "<tr><td>+90 555 000 00 02</td><td>100.00 TL</td><td>Pending</td></tr>"
                + "</table>"
                + "<p style=\"color:#667;font-size:13px;margin-top:20px\">"
                + "<a href=\"" + req.getContextPath() + "/pages/login.jsf\">Sign out</a> &middot; "
                + "<a href=\"" + req.getContextPath() + "/lab/hints\">Lab notes</a>"
                + "</p></div></body></html>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.sendRedirect(req.getContextPath() + "/pages/topup.jsf");
    }
}
