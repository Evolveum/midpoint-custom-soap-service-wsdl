/**
 * Copyright (c) 2014-2019 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

import com.evolveum.midpoint.prism.*;
import org.apache.commons.lang.Validate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.evolveum.midpoint.model.api.ModelService;
import com.evolveum.midpoint.model.common.util.AbstractModelWebService;
import com.evolveum.midpoint.prism.query.ObjectQuery;
import com.evolveum.midpoint.schema.result.OperationResult;
import com.evolveum.midpoint.task.api.Task;
import com.evolveum.midpoint.util.exception.CommonException;
import com.evolveum.midpoint.util.exception.CommunicationException;
import com.evolveum.midpoint.util.exception.ConfigurationException;
import com.evolveum.midpoint.util.exception.ExpressionEvaluationException;
import com.evolveum.midpoint.util.exception.ObjectNotFoundException;
import com.evolveum.midpoint.util.exception.PolicyViolationException;
import com.evolveum.midpoint.util.exception.SchemaException;
import com.evolveum.midpoint.util.exception.SecurityViolationException;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.xml.ns._public.common.common_3.UserType;
import com.example.midpoint.xml.ns.example_1.CustomUserType;
import com.example.midpoint.xml.ns.example_1.ExamplePortType;
import com.example.midpoint.xml.ns.example_1.Fault;
import com.example.midpoint.xml.ns.example_1.FaultCodeType;
import com.example.midpoint.xml.ns.example_1.FaultDetailsType;
import com.example.midpoint.xml.ns.example_1.SearchUserByEmailRequestType;
import com.example.midpoint.xml.ns.example_1.SearchUserByEmailResponseType;

/**
 * @author semancik
 * @author katkav
 */
@Service
public class ExampleWebService extends AbstractModelWebService implements ExamplePortType {

	private static final Trace LOGGER = TraceManager.getTrace(ExampleWebService.class);

	@Autowired ModelService modelService;
	@Autowired PrismContext prismContext;
	
	public SearchUserByEmailResponseType searchUserByEmail(SearchUserByEmailRequestType parameters)
			throws Fault {
		final String OPERATION_NAME = "searchUserByEmail";
		LOGGER.trace("Received Example WS request {}({})", OPERATION_NAME, parameters);

		String email = parameters.getEmail();
		Validate.notEmpty(email, "No email in person");

		Task task = createTaskInstance(ExampleWebService.class.getName() + OPERATION_NAME);
		auditLogin(task);
		OperationResult result = task.getResult();

		SearchUserByEmailResponseType response;
		try {
			List<PrismObject<UserType>> users = findUsers(UserType.F_EMAIL_ADDRESS, email,
					PrismConstants.STRING_IGNORE_CASE_MATCHING_RULE_NAME, task, result);

			response = new SearchUserByEmailResponseType();
			for (PrismObject<UserType> user : users) {
				// if (user != null){
				CustomUserType customUser = convertToCustomUserType(user);
				response.getUser().add(customUser);
				// response.setUid(user.getOid());
			}

		} catch (CommonException e) {
			throw handleFault(OPERATION_NAME, e, task);
		}

		return response;
	}

	private <T> List<PrismObject<UserType>> findUsers(QName propertyName, T email, QName matchingRule,
			Task task, OperationResult result) throws SchemaException, ObjectNotFoundException,
			SecurityViolationException, CommunicationException, ConfigurationException, ExpressionEvaluationException {

		ObjectQuery query = createUserSubstringQuery(propertyName, matchingRule, email);
		List<PrismObject<UserType>> foundObjects = modelService.searchObjects(UserType.class, query, null,
				task, result);
		return foundObjects;

	}
	
	private <T> ObjectQuery createUserSubstringQuery(QName property, QName matchingRule, T value)
			throws SchemaException {
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

	private Fault handleFault(String operation, CommonException e, Task task) {
		LOGGER.error("Example WS operation {} failed {}: {}",
				new Object[] { operation, e, e.getMessage(), e });
		auditLogout(task);
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
		Fault fault = new Fault(e.getMessage(), faultDetails, e);
		return fault;
	}

}
