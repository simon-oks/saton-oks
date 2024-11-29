package tg.saton;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@EnableWebSecurity
@EnableMethodSecurity
@RequestMapping("/")
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is a public endpoint!";
    }

    @GetMapping("/protected")
    public String protectedEndpoint() {
        return "This is a protected endpoint!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('AUTH_ADMIN')")
    public String adminEndpoint() {
        return "This is an admin endpoint! access for role AUTH_ADMIN";
    }

    @GetMapping("/doctor")
    @PreAuthorize("hasRole('DOCTOR')")
    public String doctorEndpoint() {
        return "This is a doctor endpoint! access for role DOCTOR";
    }

    @GetMapping("/nurse")
    @PreAuthorize("hasRole('NURSE')")
    public String nurseEndpoint() {
        return "This is a nurse endpoint! access for role NURSE";
    }

    @GetMapping("/doctorAndNurse")
    @PreAuthorize("hasRole('DOCTOR') and hasRole('NURSE')")
    public String doctorAndNurseEndpoint() {
        return "This is a doctor and nurse endpoint! access for role DOCTOR and NURSE";
    }

    @GetMapping("/doctorOrNurse")
    @PreAuthorize("hasRole('DOCTOR') or hasRole('NURSE')")
    public String doctorOrNurseEndpoint() {
        return "This is a doctor or nurse endpoint! access for role DOCTOR or NURSE";
    }

    @GetMapping("/adminOrNurse")
    @PreAuthorize("hasRole('PATIENT')")
    public String adminOrNurseEndpoint() {
        return "This is a admin or nurse endpoint! access for role AUTH_ADMIN or NURSE";
    }
}

