// File: ProfileServlet.java

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ProfileServlet extends HttpServlet {

    private Map<Integer, String> userProfiles = new HashMap<>();

    public ProfileServlet() {
        userProfiles.put(1, "User1's secret data");
        userProfiles.put(2, "User2's secret data");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String idParam = req.getParameter("id");
        if (idParam != null) {
            int id = Integer.parseInt(idParam);
            String profileData = userProfiles.get(id);

            if (profileData != null) {
                resp.getWriter().write("<html><body>");
                resp.getWriter().write("<h1>Profile Data:</h1>");
                resp.getWriter().write(profileData);  // Vulnerable point
                resp.getWriter().write("</body></html>");
            } else {
                resp.getWriter().write("Profile not found.");
            }
        } else {
            resp.getWriter().write("Please provide an ID.");
        }
    }
}
