/*
 * Copyright (c) 2010-2018 Evolveum and contributors
 *
 * This work is dual-licensed under the Apache License 2.0
 * and European Union Public License. See LICENSE file for details.
 */
package com.example.midpoint.service.infra;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.springframework.beans.factory.annotation.Autowired;

import com.evolveum.midpoint.model.api.authentication.GuiProfiledPrincipalManager;
import com.evolveum.midpoint.security.enforcer.api.SecurityEnforcer;
import com.evolveum.midpoint.task.api.TaskManager;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;

/**
 * Responsible to inject Spring authentication object before we call WS method
 */
public class SpringAuthenticationInjectorInterceptor extends AbstractPhaseInterceptor<SoapMessage> {

    private static final String OPERATION_AUTHORIZATION = SpringAuthenticationInjectorInterceptor.class.getName() + ".authorization";

    private static final Trace LOGGER = TraceManager.getTrace(SpringAuthenticationInjectorInterceptor.class);

    @Autowired
    private GuiProfiledPrincipalManager guiProfiledPrincipalManager;
    @Autowired
    private SecurityEnforcer securityEnforcer;
    @Autowired
    private TaskManager taskManager;

    // TODO cleanup - this is from model-impl
    //    private SecurityHelper securityHelper;

    public SpringAuthenticationInjectorInterceptor() {
        super(SpringAuthenticationInjectorInterceptor.class.getName(), Phase.PRE_PROTOCOL);
        getAfter().add(WSS4JInInterceptor.class.getName());
    }

    @Override
    public void handleMessage(SoapMessage message) throws Fault {
        //Note: in constructor we have specified that we will be called after we have been successfully authenticated the user through WS-Security
        //Now we will only set the Spring Authentication object based on the user found in the header
        LOGGER.trace("Intercepted message: {}", message);
        /*
        SOAPMessage saajSoapMessage = securityHelper.getSOAPMessage(message);
        if (saajSoapMessage == null) {
            LOGGER.error("No soap message in handler");
            throw createFault(WSSecurityException.ErrorCode.FAILURE);
        }
        ConnectionEnvironment connEnv = ConnectionEnvironment.create(SchemaConstants.CHANNEL_WEB_SERVICE_URI);
        String username = null;
        try {
            username = securityHelper.getUsernameFromMessage(saajSoapMessage);
            LOGGER.trace("Attempt to authenticate user '{}'", username);

            if (StringUtils.isBlank(username)) {
                message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
                securityHelper.auditLoginFailure(username, null, connEnv, "Empty username");
                throw createFault(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            MidPointPrincipal principal = null;
            try {
                principal = guiProfiledPrincipalManager.getPrincipal(username, UserType.class);
            } catch (SchemaException e) {
                handlePrincipalException(message, username, connEnv, "Schema error", e);
            } catch (CommunicationException e) {
                handlePrincipalException(message, username, connEnv, "Communication error", e);
            } catch (ConfigurationException e) {
                handlePrincipalException(message, username, connEnv, "Configuration error", e);
            } catch (SecurityViolationException e) {
                handlePrincipalException(message, username, connEnv, "Security violation", e);
            } catch (ExpressionEvaluationException e) {
                handlePrincipalException(message, username, connEnv, "Expression error", e);
            }
            LOGGER.trace("Principal: {}", principal);
            if (principal == null) {
                message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
                securityHelper.auditLoginFailure(username, null, connEnv, "No user");
                throw createFault(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            // Account validity and credentials and all this stuff should be already checked
            // in the password callback

            Authentication authentication = new UsernamePasswordAuthenticationToken(principal, null);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String operationName;
            try {
                operationName = DOMUtil.getFirstChildElement(saajSoapMessage.getSOAPBody()).getLocalName();
            } catch (SOAPException e) {
                LOGGER.debug("Access to web service denied for user '{}': SOAP error: {}",
                        username, e.getMessage(), e);
                message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
                securityHelper.auditLoginFailure(username, principal.getFocus(), connEnv, "SOAP error: " + e.getMessage());
                throw new Fault(e);
            }

            // AUTHORIZATION

            Task task = taskManager.createTaskInstance(OPERATION_AUTHORIZATION);
            OperationResult result = task.getResult();

            boolean isAuthorized;
            try {
                isAuthorized = securityEnforcer.isAuthorized(AuthorizationConstants.AUTZ_WS_ALL_URL, AuthorizationPhaseType.REQUEST, AuthorizationParameters.EMPTY, null, task, result);
                LOGGER.trace("Determined authorization for web service access (action: {}): {}", AuthorizationConstants.AUTZ_WS_ALL_URL, isAuthorized);
            } catch (SchemaException | ObjectNotFoundException | ExpressionEvaluationException | CommunicationException | ConfigurationException | SecurityViolationException e) {
                LOGGER.debug("Access to web service denied for user '{}': internal error: {}",
                        username, e.getMessage(), e);
                message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
                securityHelper.auditLoginFailure(username, principal.getFocus(), connEnv, "Schema error: " + e.getMessage());
                throw createFault(WSSecurityException.ErrorCode.FAILURE);
            }
            if (!isAuthorized) {
                String action = QNameUtil.qNameToUri(new QName(AuthorizationConstants.NS_AUTHORIZATION_WS, operationName));
                try {
                    isAuthorized = securityEnforcer.isAuthorized(action, AuthorizationPhaseType.REQUEST, AuthorizationParameters.EMPTY, null, task, result);
                    LOGGER.trace("Determined authorization for web service operation {} (action: {}): {}", operationName, action, isAuthorized);
                } catch (SchemaException | ObjectNotFoundException | ExpressionEvaluationException | CommunicationException | ConfigurationException | SecurityViolationException e) {
                    LOGGER.debug("Access to web service denied for user '{}': schema error: {}",
                            username, e.getMessage(), e);
                    message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
                    securityHelper.auditLoginFailure(username, principal.getFocus(), connEnv, "Internal error: " + e.getMessage());
                    throw createFault(WSSecurityException.ErrorCode.FAILURE);
                }
            }
            if (!isAuthorized) {
                LOGGER.debug("Access to web service denied for user '{}': not authorized", username);
                message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
                securityHelper.auditLoginFailure(username, principal.getFocus(), connEnv, "Not authorized");
                throw createFault(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

        } catch (WSSecurityException e) {
            LOGGER.debug("Access to web service denied for user '{}': security exception: {}",
                    username, e.getMessage(), e);
            message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
            securityHelper.auditLoginFailure(username, null, connEnv, "Security exception: " + e.getMessage());
            throw new Fault(e, e.getFaultCode());
        } catch (ObjectNotFoundException e) {
            LOGGER.debug("Access to web service denied for user '{}': object not found: {}",
                    username, e.getMessage(), e);
            message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
            securityHelper.auditLoginFailure(username, null, connEnv, "No user");
            throw createFault(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        // Avoid auditing login attempt again if the operation fails on internal authorization
        message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);

        LOGGER.debug("Access to web service allowed for user '{}'", username);
        */
    }

    /*
    private void handlePrincipalException(SoapMessage message, String username, ConnectionEnvironment connEnv, String errorDesc, Exception e) {
        LOGGER.debug("Access to web service denied for user '{}': {}: {}",
                username, errorDesc, e.getMessage(), e);
        message.put(SecurityHelper.CONTEXTUAL_PROPERTY_AUDITED_NAME, true);
        securityHelper.auditLoginFailure(username, null, connEnv, errorDesc + ": " + e.getMessage());
        throw new Fault(e);
    }

    private Fault createFault(ErrorCode code) {
        return new Fault(new WSSecurityException(code), code.getQName());
    }
         */
}
