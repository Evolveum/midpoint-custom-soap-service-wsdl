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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.evolveum.midpoint.authentication.api.config.AuthenticationEvaluator;
import com.evolveum.midpoint.model.api.authentication.GuiProfiledPrincipalManager;
import com.evolveum.midpoint.model.api.context.PasswordAuthenticationContext;
import com.evolveum.midpoint.schema.constants.SchemaConstants;
import com.evolveum.midpoint.security.api.ConnectionEnvironment;
import com.evolveum.midpoint.security.api.MidPointPrincipal;
import com.evolveum.midpoint.util.exception.*;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.xml.ns._public.common.common_3.FocusType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.UserType;

/**
 * Validator of UsernameToken - tries to authenticate with provided username and password.
 * This validator prepares MidPointPrincipal and sets it in the security context holder.
 * Authorizations are left for an interceptor as it is easier to figure out operation name there.
 */
public class WsUsernameTokenValidator implements Validator {

    // logs on info level for demonstration purposes, adjust accordingly
    private static final Trace LOGGER = TraceManager.getTrace(WsUsernameTokenValidator.class);

    @Autowired
    private AuthenticationEvaluator<PasswordAuthenticationContext> passwordAuthenticationEvaluator;

    @Autowired
    private GuiProfiledPrincipalManager principalManager;

    @Override
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        // few lines taken from default UsernameTokenValidator, but we don't want it all
        if (credential == null || credential.getUsernametoken() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCredential");
        }

        UsernameToken usernameToken = credential.getUsernametoken();
        PasswordAuthenticationContext authCtx = new PasswordAuthenticationContext(
                usernameToken.getName(), usernameToken.getPassword(), UserType.class);
        LOGGER.info("WS validation: username='{}', password type='{}'",
                usernameToken.getName(), usernameToken.getPasswordType());

        ConnectionEnvironment connEnv =
                ConnectionEnvironment.create(SchemaConstants.CHANNEL_WEB_SERVICE_URI);
        try {
            FocusType user = passwordAuthenticationEvaluator.checkCredentials(connEnv, authCtx);
            MidPointPrincipal principal = principalManager.getPrincipal(user.asPrismObject());
            SecurityContextHolder.getContext().setAuthentication(
                    new PreAuthenticatedAuthenticationToken(principal, null));

            return credential;
        } catch (AccessDeniedException | AuthenticationException | ExpressionEvaluationException
                | SchemaException | CommunicationException | ConfigurationException
                | SecurityViolationException e) {
            LOGGER.error("Access/auth exception in validate - {}: {}",
                    e.getClass().getSimpleName(), e.getMessage());
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION,
                    "generic.EmptyMessage", new Object[] { e.getMessage() });
        }
    }
}
