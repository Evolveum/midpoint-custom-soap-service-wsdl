/*
 * Copyright (C) 2014-2020 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
        registration.setLoadOnStartup(1);
        // Choose mapping that does NOT collide with other paths of midPoint (REST, UI).
        // CXF servlet takes over this mapping completely and anything it overshadows stops working.
        // This is also the path that needs to be ignored in flexi-auth (see README) if custom
        // other authentication is used (such as WS-Security in this example).
        registration.addUrlMappings("/soap/*");

        return registration;
    }
}
