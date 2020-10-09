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

import org.apache.cxf.logging.FaultListener;
import org.apache.cxf.message.Message;

import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;

public class WsFaultListener implements FaultListener {

    private static final Trace LOGGER = TraceManager.getTrace(WsFaultListener.class);

    /**
     * Return true to delegate to default fault handling, false if this method took care of the fault.
     */
    @Override
    public boolean faultOccurred(Exception exception, String description, Message message) {
        LOGGER.error("Handling fault {}: {} - {}",
                exception.getClass().getName(), description, message, exception);

        // custom logic here, nothing for this example
        // - we can handle message causes better if they are buried too deep
        // - we can add auditing here

        // returning false and letting the default logic handle the exception
        return false;
    }
}
