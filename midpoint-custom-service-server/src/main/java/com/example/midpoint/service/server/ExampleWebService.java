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

import java.util.List;
import javax.xml.namespace.QName;

import com.example.midpoint.xml.ns.example_1.*;
import org.apache.commons.lang.Validate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.evolveum.midpoint.audit.api.AuditService;
import com.evolveum.midpoint.model.api.ModelService;
import com.evolveum.midpoint.prism.PrismConstants;
import com.evolveum.midpoint.prism.PrismContext;
import com.evolveum.midpoint.prism.PrismObject;
import com.evolveum.midpoint.prism.query.ObjectQuery;
import com.evolveum.midpoint.schema.constants.SchemaConstants;
import com.evolveum.midpoint.schema.result.OperationResult;
import com.evolveum.midpoint.security.api.MidPointPrincipal;
import com.evolveum.midpoint.task.api.Task;
import com.evolveum.midpoint.task.api.TaskManager;
import com.evolveum.midpoint.util.exception.*;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.xml.ns._public.common.common_3.FocusType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.UserType;

@Service
public class ExampleWebService implements ExamplePortType {

    private static final Trace LOGGER = TraceManager.getTrace(ExampleWebService.class);

    @Autowired private ModelService modelService;
    @Autowired private PrismContext prismContext;
    @Autowired private TaskManager taskManager;
    @Autowired protected AuditService auditService;

    public SearchUserByEmailResponseType searchUserByEmail(SearchUserByEmailRequestType parameters)
            throws Fault {
        final String OPERATION_NAME = "searchUserByEmail";
        LOGGER.info("Received Example WS request {}({})", OPERATION_NAME, parameters);

        String email = parameters.getEmail();
        Validate.notEmpty(email, "No email in person");

        Task task = createTaskInstance(OPERATION_NAME);
        OperationResult result = task.getResult();

        try {
            List<PrismObject<UserType>> users = findUsers(UserType.F_EMAIL_ADDRESS, email,
                    PrismConstants.STRING_IGNORE_CASE_MATCHING_RULE_NAME, task, result);
            // task result check omitted

            SearchUserByEmailResponseType response = new SearchUserByEmailResponseType();
            for (PrismObject<UserType> user : users) {
                CustomUserType customUser = convertToCustomUserType(user);
                response.getUser().add(customUser);
            }
            return response;
        } catch (CommonException e) {
            throw handleFault(OPERATION_NAME, e);
        }
    }

    private <T> List<PrismObject<UserType>> findUsers(
            QName propertyName, T email, QName matchingRule, Task task, OperationResult result)
            throws SchemaException, ObjectNotFoundException,
            SecurityViolationException, CommunicationException, ConfigurationException, ExpressionEvaluationException {

        ObjectQuery query = createUserSubstringQuery(propertyName, matchingRule, email);
        List<PrismObject<UserType>> foundObjects = modelService.searchObjects(UserType.class, query, null,
                task, result);
        return foundObjects;
    }

    private <T> ObjectQuery createUserSubstringQuery(QName property, QName matchingRule, T value) {
        return prismContext.queryFor(UserType.class)
                .item(property)
                .startsWith(value)
                .matching(matchingRule)
                .build();
    }

    private CustomUserType convertToCustomUserType(PrismObject<UserType> user) {
        CustomUserType customUser = new CustomUserType();
        UserType userType = user.asObjectable();

        customUser.setUsername(user.getName().getOrig());

        if (userType.getFullName() != null) {
            customUser.setFullname(userType.getFullName().getOrig());
        }

        if (userType.getEmailAddress() != null) {
            customUser.setEmail(userType.getEmailAddress());
        }

        return customUser;
    }

    private Fault handleFault(String operation, CommonException e) {
        LOGGER.error("Example WS operation {} failed: {}", operation, e.getMessage(), e);
        FaultDetailsType faultDetails = new FaultDetailsType();
        FaultCodeType faultCode;
        if (e instanceof SchemaException) {
            faultCode = FaultCodeType.SCHEMA_VIOLATION;
        } else if (e instanceof SecurityViolationException) {
            faultCode = FaultCodeType.SECURITY_VIOLATION;
        } else if (e instanceof PolicyViolationException) {
            faultCode = FaultCodeType.POLICY_VIOLATION;
        } else if (e instanceof CommunicationException) {
            faultCode = FaultCodeType.COMMUNICATION_ERROR;
        } else {
            faultCode = FaultCodeType.INTERNAL_ERROR;
        }
        faultDetails.setCode(faultCode);
        faultDetails.getDetail().add(e.getMessage());
        return new Fault(e.getMessage(), faultDetails, e);
    }

    private static final String OP_NAME_PREFIX = ExampleWebService.class.getName() + '#';

    private Task createTaskInstance(String operationName) {
        Task task = taskManager.createTaskInstance(OP_NAME_PREFIX + operationName);
        setTaskOwner(task);
        task.setChannel(SchemaConstants.CHANNEL_WEB_SERVICE_URI);
        return task;
    }

    private void setTaskOwner(Task task) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new SystemException("Failed to get authentication object");
        }
        FocusType focusType = ((MidPointPrincipal) (SecurityContextHolder.getContext().getAuthentication().getPrincipal())).getFocus();
        task.setOwner(focusType.asPrismObject());
    }
}
