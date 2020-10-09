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

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.springframework.beans.factory.annotation.Autowired;

import com.evolveum.midpoint.schema.constants.SchemaConstants;
import com.evolveum.midpoint.schema.result.OperationResult;
import com.evolveum.midpoint.security.api.AuthorizationConstants;
import com.evolveum.midpoint.security.enforcer.api.AuthorizationParameters;
import com.evolveum.midpoint.security.enforcer.api.SecurityEnforcer;
import com.evolveum.midpoint.task.api.Task;
import com.evolveum.midpoint.task.api.TaskManager;
import com.evolveum.midpoint.util.exception.*;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.xml.ns._public.common.common_3.AuthorizationPhaseType;

/**
 * Responsible for cleanup of Spring's security context after the WS method call.
 */
public class WsAuthorizationInterceptor extends AbstractPhaseInterceptor<SoapMessage> {

    private static final Trace LOGGER = TraceManager.getTrace(WsUsernameTokenValidator.class);

    private static final String OPERATION_AUTHORIZATION =
            WsUsernameTokenValidator.class.getName() + ".authorization";

    // custom WS authorization constants
    private static final String NS_AUTHORIZATION_WS =
            AuthorizationConstants.NS_SECURITY_PREFIX + "authorization-custom-ws";
    private static final String AUTZ_ALL_URL = authorizationUrl("all");

    @Autowired
    private SecurityEnforcer securityEnforcer;

    @Autowired
    private TaskManager taskManager;

    public WsAuthorizationInterceptor() {
        // we set PRE_INVOKE phase, e.g. PRE_PROTOCOL is too soon to extract operation name easily
        super(WsAuthorizationInterceptor.class.getName(), Phase.PRE_INVOKE);
    }

    @Override
    public void handleMessage(SoapMessage message) throws Fault {
        try {
            Task task = taskManager.createTaskInstance(OPERATION_AUTHORIZATION);
            task.setChannel(SchemaConstants.CHANNEL_WEB_SERVICE_URI);
            OperationResult result = task.getResult();

            // in our example granted by role: Custom WS User
            if (securityEnforcer.isAuthorized(AUTZ_ALL_URL, AuthorizationPhaseType.REQUEST,
                    AuthorizationParameters.EMPTY, null, task, result)) {
                return;
            }

            // for the only operation granted by role: Custom WS User - SearchUserByEmail
            QName operationName = message.getExchange().getBindingOperationInfo().getName();
            String action = authorizationUrl(operationName.getLocalPart());
            if (securityEnforcer.isAuthorized(action, AuthorizationPhaseType.REQUEST,
                    AuthorizationParameters.EMPTY, null, task, result)) {
                return;
            }

            var errorCode = WSSecurityException.ErrorCode.FAILED_AUTHENTICATION;
            throw new Fault(new WSSecurityException(errorCode), errorCode.getQName());
        } catch (ObjectNotFoundException | ConfigurationException | SecurityViolationException
                | CommunicationException | ExpressionEvaluationException | SchemaException e) {
            LOGGER.error("Access/auth exception in validate - {}: {}",
                    e.getClass().getSimpleName(), e.getMessage());
            throw new Fault(
                    new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e.getMessage()));
        }
    }

    /**
     * This has the same meaning as "operationUrl" when checking if the user is authorized.
     * Parameter opName is just local part of the SOAP operation QName as it is prefixed by
     * custom {@link #NS_AUTHORIZATION_WS} constant (not from midPoint, but from this overlay).
     */
    private static String authorizationUrl(String opName) {
        return NS_AUTHORIZATION_WS + '#' + opName;
    }
}
