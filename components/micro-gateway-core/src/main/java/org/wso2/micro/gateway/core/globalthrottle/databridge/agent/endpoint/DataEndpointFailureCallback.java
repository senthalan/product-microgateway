/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.micro.gateway.core.globalthrottle.databridge.agent.endpoint;

import org.wso2.carbon.databridge.commons.Event;

import java.util.List;

/**
 * This interface is used to implement a call back for get the notifications upon the unsuccessful event publishing.
 */
public interface DataEndpointFailureCallback {

    /**
     * Notifies the The failed events, and should try to send the events again successfully.
     * In case if this couldn't send the events, then the unsuccessful events list needs to be returned back.
     *
     * @param events List failed events
     */
    public void tryResendEvents(List<Event> events, DataEndpoint failedEP);

}
