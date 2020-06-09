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
package org.wso2.micro.gateway.core.globalthrottle.databridge.agent.endpoint.binary;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.wso2.micro.gateway.core.globalthrottle.databridge.agent.AgentHolder;
import org.wso2.micro.gateway.core.globalthrottle.databridge.agent.client.AbstractSecureClientPoolFactory;
import org.wso2.micro.gateway.core.globalthrottle.databridge.agent.conf.DataEndpointConfiguration;
import org.wso2.micro.gateway.core.globalthrottle.databridge.agent.exception.DataEndpointException;
import org.wso2.micro.gateway.core.globalthrottle.databridge.agent.util.SecurityConstants;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * This is a Binary Transport secure implementation for AbstractSecureClientPoolFactory to be used by BinaryEndpoint.
 */
public class BinarySecureClientPoolFactory extends AbstractSecureClientPoolFactory {
    private static final Logger log = LogManager.getLogger(BinarySecureClientPoolFactory.class);
    private static SSLSocketFactory sslSocketFactory;

    public BinarySecureClientPoolFactory(String trustStore, String trustStorePassword) {
        super(trustStore, trustStorePassword);
        SSLContext ctx;
        try {
            ctx = createSSLContext();
            sslSocketFactory = ctx.getSocketFactory();
        } catch (DataEndpointException e) {
            log.error("Error while initializing the SSL Context with provided parameters" +
                    e.getErrorMessage(), e);
            log.warn("Default SSLSocketFactory will be used for the data publishing clients.");
            sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
    }

    @Override
    public Object createClient(String protocol, String hostName, int port) throws DataEndpointException {
        if (protocol.equalsIgnoreCase(DataEndpointConfiguration.Protocol.SSL.toString())) {
            int timeout = AgentHolder.getInstance().getDataEndpointAgent().getAgentConfiguration()
                    .getSocketTimeoutMS();
            String sslProtocols = AgentHolder.getInstance().getDataEndpointAgent().getAgentConfiguration()
                    .getSslEnabledProtocols();
            String ciphers = AgentHolder.getInstance().getDataEndpointAgent().getAgentConfiguration().getCiphers();

            try {
                SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(hostName, port);
                sslSocket.setSoTimeout(timeout);

                if (sslProtocols != null && sslProtocols.length() != 0) {
                    String[] sslProtocolsArray = sslProtocols.split(",");
                    sslSocket.setEnabledProtocols(sslProtocolsArray);
                }

                if (ciphers != null && ciphers.length() != 0) {
                    String[] ciphersArray = ciphers.replaceAll(" ", "").split(",");
                    sslSocket.setEnabledCipherSuites(ciphersArray);
                } else {
                    sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
                }
                return sslSocket;
            } catch (IOException e) {
                throw new DataEndpointException("Error while opening socket to " + hostName + ":" + port + ". " +
                        e.getMessage(), e);
            }
        } else {
            throw new DataEndpointException("Unsupported protocol: " + protocol + ". Currently only " +
                    DataEndpointConfiguration.Protocol.SSL.toString() + " supported.");
        }
    }

    @Override
    public boolean validateClient(Object client) {
        Socket socket = (Socket) client;
        return socket.isConnected();
    }

    @Override
    public void terminateClient(Object client) {
        Socket socket = null;
        try {
            socket = (Socket) client;
            socket.close();
        } catch (IOException e) {
            log.warn("Cannot close the socket successfully from " + socket.getLocalAddress().getHostAddress()
                    + ":" + socket.getPort());
        }
    }

    private SSLContext createSSLContext() throws DataEndpointException {
        FileInputStream fileInputStream;
        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance(SecurityConstants.SSLCONTEXT_ALGORITHM);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(SecurityConstants.TMF_ALGORITHM);
            KeyStore keyStore = KeyStore.getInstance(SecurityConstants.KEYSTORE_TYPE);
            fileInputStream = new FileInputStream(this.getTrustStore());
            keyStore.load(fileInputStream, this.getTrustStorePassword() != null ?
                    this.getTrustStorePassword().toCharArray() : null);
            trustManagerFactory.init(keyStore);
            ctx.init(null, trustManagerFactory.getTrustManagers(), null);
            return ctx;
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyManagementException |
                KeyStoreException e) {
            throw new DataEndpointException("Error while creating the SSLContext with instance type : TLS." +
                    e.getMessage(), e);
        }
    }
}
