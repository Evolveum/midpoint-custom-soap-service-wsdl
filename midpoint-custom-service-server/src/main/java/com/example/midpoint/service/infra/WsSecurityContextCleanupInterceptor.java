/*
 * Copyright (C) 2010-2020 Evolveum
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
