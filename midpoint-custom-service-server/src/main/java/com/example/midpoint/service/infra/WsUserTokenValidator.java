/*
 * Copyright (c) 2010-2017 Evolveum and contributors
 *
 * This work is dual-licensed under the Apache License 2.0
 * and European Union Public License. See LICENSE file for details.
 */
package com.example.midpoint.service.infra;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

import com.evolveum.midpoint.model.api.AuthenticationEvaluator;
import com.evolveum.midpoint.model.api.authentication.GuiProfiledPrincipal;
import com.evolveum.midpoint.model.api.context.PasswordAuthenticationContext;
import com.evolveum.midpoint.schema.constants.SchemaConstants;
import com.evolveum.midpoint.security.api.ConnectionEnvironment;
import com.evolveum.midpoint.security.api.MidPointPrincipal;
import com.evolveum.midpoint.util.exception.*;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.xml.ns._public.common.common_3.*;

/**
 * Validator of user token - tries to authenticated with provided username and password.
 */
public class WsUserTokenValidator implements Validator {

    // logs on info level for demonstration purposes, adjust accordingly
    private static final Trace LOGGER = TraceManager.getTrace(WsUserTokenValidator.class);

    @Autowired
    private AuthenticationEvaluator<PasswordAuthenticationContext> passwordAuthenticationEvaluator;

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
            // TODO - cleanup: following lines were originally responsibility of SAIInterceptor, which I'd like to remove comletely
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(new MidPointPrincipal(user), null));

            // TODO do we want to recordAuthenticationSuccess, how?

            return credential;
        } catch (AccessDeniedException | AuthenticationException e) {
            LOGGER.error("Access/auth exception in validate - {}: {}",
                    e.getClass().getSimpleName(), e.getMessage());
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e.getMessage());
        }
    }
}
