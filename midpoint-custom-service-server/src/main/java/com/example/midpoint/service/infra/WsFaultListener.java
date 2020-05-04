/*
 * Copyright (c) 2015-2020 Evolveum and contributors
 *
 * This work is dual-licensed under the Apache License 2.0
 * and European Union Public License. See LICENSE file for details.
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
