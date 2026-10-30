/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.wss4j.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.cache.ReplayCacheFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.saml.SAML2CallbackHandler;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.validate.SamlTokenValidatorImpl;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class ReplayTest extends AbstractTestBase {

    private static final Pattern NONCE_PATTERN = Pattern.compile("(<[^>]*Nonce[^>]*>)([^<]*)(</)");

    private ReplayCache createCache(String key) throws WSSecurityException {
        ReplayCacheFactory replayCacheFactory = ReplayCacheFactory.newInstance();
        byte[] nonceValue;
        try {
            nonceValue = WSSConstants.generateBytes(10);
            String cacheKey = key + Base64.encode(nonceValue);
            return replayCacheFactory.newReplayCache(cacheKey, null);
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    @Test
    public void testReplayedTimestamp() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{" + WSConstants.WSU_NS + "}Timestamp;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        ReplayCache replayCache = createCache("wss4j.timestamp.cache-");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setTimestampReplayCache(replayCache);
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setTimestampReplayCache(replayCache);
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
                Assert.assertEquals("The message has expired", e.getCause().getMessage());
            }
        }
        
        replayCache.close();
    }

    @Test
    public void testUsernameToken() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSSE_USERNAME_TOKEN.getNamespaceURI(), WSSConstants.TAG_WSSE_USERNAME_TOKEN.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now test verification:
        ReplayCache replayCache = createCache("wss4j.nonce.cache-");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setNonceReplayCache(replayCache);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSSE_USERNAME_TOKEN.getNamespaceURI(), WSSConstants.TAG_WSSE_USERNAME_TOKEN.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }

        //done UsernameToken; now test verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setNonceReplayCache(replayCache);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
            }
        }

        replayCache.close();
    }

    /**
     * The Nonce replay cache must be keyed on the decoded Nonce, not on the raw text of the Nonce
     * element. Base64 decoding ignores whitespace, so a replayed token whose Nonce has merely been
     * line-wrapped still authenticates - the password digest is computed over the decoded bytes -
     * and must still be detected as a replay.
     */
    @Test
    public void testReplayedUsernameTokenWithEquivalentNonceEncoding() throws Exception {
        String genuineMessage = createUsernameTokenMessage();

        Matcher matcher = NONCE_PATTERN.matcher(genuineMessage);
        Assert.assertTrue("No Nonce element was found", matcher.find());
        String nonce = matcher.group(2);

        // Wrap the Nonce across two lines. Base64 decoding ignores the newline, so this Nonce
        // decodes to exactly the same bytes and the password digest still verifies.
        String equivalentNonce = nonce.substring(0, 4) + "\n" + nonce.substring(4);
        Assert.assertNotEquals(nonce, equivalentNonce);
        Assert.assertArrayEquals("The rewritten Nonce must decode to the same bytes",
                                 org.apache.commons.codec.binary.Base64.decodeBase64(nonce),
                                 org.apache.commons.codec.binary.Base64.decodeBase64(equivalentNonce));

        String replayedMessage = genuineMessage.substring(0, matcher.start(2))
            + equivalentNonce + genuineMessage.substring(matcher.end(2));

        ReplayCache replayCache = createCache("wss4j.nonce.cache-");

        //the genuine UsernameToken must verify
        processUsernameTokenMessage(genuineMessage, replayCache);

        //the rewritten Nonce decodes to the same bytes, so this is a replay
        try {
            processUsernameTokenMessage(replayedMessage, replayCache);
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
        }

        replayCache.close();
    }

    /**
     * The streaming UsernameToken validator decodes the Nonce with commons-codec, which also skips
     * characters outside the Base-64 alphabet, accepts missing padding and ignores anything after
     * the padding. Each of these rewrites still authenticates on its own, so each must be detected
     * as a replay of the genuine token.
     */
    @Test
    public void testReplayedUsernameTokenWithLenientlyDecodedNonce() throws Exception {
        String genuineMessage = createUsernameTokenMessage();

        Matcher matcher = NONCE_PATTERN.matcher(genuineMessage);
        Assert.assertTrue("No Nonce element was found", matcher.find());
        String nonce = matcher.group(2);
        Assert.assertTrue("Expected a padded Nonce: " + nonce, nonce.endsWith("="));

        String[] equivalentNonces = {
            nonce.replace("=", ""),                           // missing padding
            nonce.substring(0, 4) + "!" + nonce.substring(4), // character outside the alphabet
            nonce + "QUFB",                                   // data after the padding
        };

        for (String equivalentNonce : equivalentNonces) {
            Assert.assertArrayEquals("The rewritten Nonce must decode to the same bytes: " + equivalentNonce,
                                     org.apache.commons.codec.binary.Base64.decodeBase64(nonce),
                                     org.apache.commons.codec.binary.Base64.decodeBase64(equivalentNonce));
            String replayedMessage = genuineMessage.substring(0, matcher.start(2))
                + equivalentNonce + genuineMessage.substring(matcher.end(2));

            //on its own, the rewritten token authenticates: its password digest still verifies
            ReplayCache freshCache = createCache("wss4j.nonce.cache-");
            processUsernameTokenMessage(replayedMessage, freshCache);
            freshCache.close();

            //after the genuine token, it is a replay
            ReplayCache replayCache = createCache("wss4j.nonce.cache-");
            processUsernameTokenMessage(genuineMessage, replayCache);
            try {
                processUsernameTokenMessage(replayedMessage, replayCache);
                Assert.fail("Exception expected for the rewritten Nonce " + equivalentNonce);
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
            }
            replayCache.close();
        }
    }

    /**
     * A UsernameToken whose password fails to verify must not leave its Nonce in the replay cache.
     * Otherwise an attacker can replay a genuine token with a corrupted Password and send that
     * first: it is rejected, but it has claimed the genuine token's Nonce, so the genuine token is
     * then rejected as a replay when it arrives.
     */
    @Test
    public void testNonceCacheNotPoisonedByInvalidPassword() throws Exception {
        String genuineMessage = createUsernameTokenMessage();

        // Corrupt the password digest, leaving the Nonce - the whole cache key - untouched
        Matcher matcher =
            Pattern.compile("(<[^>]*Password[^>]*>)([^<]*)(</)").matcher(genuineMessage);
        Assert.assertTrue("No Password element was found", matcher.find());
        String password = matcher.group(2);
        String corruptedPassword =
            (password.charAt(0) == 'A' ? "B" : "A") + password.substring(1);

        String tamperedMessage = genuineMessage.substring(0, matcher.start(2))
            + corruptedPassword + genuineMessage.substring(matcher.end(2));
        Assert.assertNotEquals(genuineMessage, tamperedMessage);

        ReplayCache replayCache = createCache("wss4j.nonce.cache-");

        //the tampered token must be rejected, as its password digest no longer verifies
        try {
            processUsernameTokenMessage(tamperedMessage, replayCache);
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
        }

        //...and it must not have cached the genuine token's Nonce on its way out
        processUsernameTokenMessage(genuineMessage, replayCache);

        //replay detection must still work for the genuine token itself
        try {
            processUsernameTokenMessage(genuineMessage, replayCache);
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
        }

        replayCache.close();
    }

    private String createUsernameTokenMessage() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        String action = WSHandlerConstants.USERNAME_TOKEN;
        Properties properties = new Properties();
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }

    private void processUsernameTokenMessage(String message, ReplayCache replayCache) throws Exception {
        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setNonceReplayCache(replayCache);
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(
                xmlInputFactory.createXMLStreamReader(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8))));

        Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSSE_USERNAME_TOKEN.getNamespaceURI(),
                                                            WSSConstants.TAG_WSSE_USERNAME_TOKEN.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 1);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion. This
     * is just a sanity test to make sure that it is possible to send the SAML token twice, as
     * no "OneTimeUse" Element is defined there is no problem with replaying it.
     * with a OneTimeUse Element
     */
    @Test
    public void testEhCacheReplayedSAML2() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // process SAML Token
        ReplayCache replayCache = createCache("wss4j.saml.one.time.use.cache-");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();

            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_SAML2_ASSERTION, validator);
            securityProperties.addValidator(WSSConstants.TAG_SAML_ASSERTION, validator);

            securityProperties.setSamlOneTimeUseReplayCache(replayCache);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.assertNotNull(document);
        }

        // now process SAML Token again
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();

            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_SAML2_ASSERTION, validator);
            securityProperties.addValidator(WSSConstants.TAG_SAML_ASSERTION, validator);

            securityProperties.setSamlOneTimeUseReplayCache(replayCache);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.assertNotNull(document);
        }
        
        replayCache.close();
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a OneTimeUse Element
     */
    @Test
    public void testEhCacheReplayedSAML2OneTimeUse() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);
            conditions.setOneTimeUse(true);
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // process SAML Token
        ReplayCache replayCache = createCache("wss4j.saml.one.time.use.cache-");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();

            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_SAML2_ASSERTION, validator);
            securityProperties.addValidator(WSSConstants.TAG_SAML_ASSERTION, validator);

            securityProperties.setSamlOneTimeUseReplayCache(replayCache);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.assertNotNull(document);
        }

        // now process SAML Token again
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();

            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_SAML2_ASSERTION, validator);
            securityProperties.addValidator(WSSConstants.TAG_SAML_ASSERTION, validator);

            securityProperties.setSamlOneTimeUseReplayCache(replayCache);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
            }
        }
        
        replayCache.close();
    }

}
