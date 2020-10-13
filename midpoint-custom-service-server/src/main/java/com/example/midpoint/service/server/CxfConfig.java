package com.example.midpoint.service.server;

import org.apache.cxf.transport.servlet.CXFServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Additional configuration setting up CXF servlet.
 * Before midPoint version 4.2 this was part of the midPoint proper but is not anymore.
 */
@Configuration
public class CxfConfig {

    @Bean
    public ServletRegistrationBean<CXFServlet> cxfServlet() {
        ServletRegistrationBean<CXFServlet> registration = new ServletRegistrationBean<>();
        registration.setServlet(new CXFServlet());
        registration.addInitParameter("service-list-path", "midpointservices");
        registration.setLoadOnStartup(1);
        // Choose mapping that does NOT collide with other paths of midPoint (REST, UI).
        // This is also the path that needs to be ignored in flexi-auth (see README) if custom
        // other authentication is used (such as WS-Security in this example).
        registration.addUrlMappings("/soap/*");

        return registration;
    }
}
