package com.simpleoauth2server.Controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CustomErrorController implements ErrorController {

    @GetMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        // Get error status
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);

        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());

            // Add status code to the model
            model.addAttribute("statusCode", statusCode);

            // Add appropriate error message
            if (statusCode == HttpStatus.NOT_FOUND.value()) {
                model.addAttribute("errorTitle", "Page Not Found");
                model.addAttribute("errorMessage", "The requested page could not be found.");
            } else if (statusCode == HttpStatus.FORBIDDEN.value()) {
                model.addAttribute("errorTitle", "Access Denied");
                model.addAttribute("errorMessage", "You do not have permission to access this resource.");
                return "error-page"; // Use your existing access-denied page
            } else if (statusCode == HttpStatus.UNAUTHORIZED.value()) {
                model.addAttribute("errorTitle", "Authentication Required");
                model.addAttribute("errorMessage", "You must be logged in to access this resource.");
                return "redirect:/custom-login"; // Redirect to login page
            } else {
                model.addAttribute("errorTitle", "Error Occurred");
                model.addAttribute("errorMessage", errorMessage != null ?
                        errorMessage : "An unexpected error occurred.");
            }
        } else {
            model.addAttribute("errorTitle", "Error Occurred");
            model.addAttribute("errorMessage", "An unexpected error occurred.");
        }

        // Check if OAuth2 error parameters exist
        String oauth2Error = request.getParameter("error");
        if (oauth2Error != null) {
            model.addAttribute("oauth2Error", oauth2Error);
            model.addAttribute("oauth2ErrorDescription", request.getParameter("error_description"));
        }

        return "error-page";
    }
}