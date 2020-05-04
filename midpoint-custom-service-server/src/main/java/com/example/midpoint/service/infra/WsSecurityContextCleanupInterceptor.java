/*
 * Copyright (c) 2010-2020 Evolveum and contributors
 *
 * This work is dual-licensed under the Apache License 2.0
 * and European Union Public License. See LICENSE file for details.
 */
package com.example.midpoint.service.infra;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Responsible for cleanup of Spring's security context after the WS method call.
 */
public class WsSecurityContextCleanupInterceptor extends AbstractPhaseInterceptor<SoapMessage> {

    public WsSecurityContextCleanupInterceptor() {
        super(WsSecurityContextCleanupInterceptor.class.getName(), Phase.POST_INVOKE);
    }

    @Override
    public void handleMessage(SoapMessage message) throws Fault {
        SecurityContextHolder.getContext().setAuthentication(null);
    }
}
