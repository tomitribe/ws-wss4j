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

package org.apache.wss4j.common.derivedKey;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.Assert;
import org.junit.Test;

public class DerivedKeyUtilsTest extends Assert {

    private static final byte[] SECRET = "0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] NONCE = "abcdefghijklmnop".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @Test
    public void rejectsPositiveDerivedKeyLengthsBelowMinimum() throws Exception {
        try {
            DerivedKeyUtils.deriveKey(
                ConversationConstants.DerivationAlgorithm.P_SHA_1,
                null,
                DerivedKeyUtils.MINIMUM_DERIVED_KEY_LENGTH - 1,
                SECRET,
                NONCE,
                0);
            fail("Expected failure on a derived key length below the minimum");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    @Test
    public void acceptsMinimumDerivedKeyLength() throws Exception {
        byte[] key = DerivedKeyUtils.deriveKey(
            ConversationConstants.DerivationAlgorithm.P_SHA_1,
            null,
            DerivedKeyUtils.MINIMUM_DERIVED_KEY_LENGTH,
            SECRET,
            NONCE,
            0);

        assertEquals(DerivedKeyUtils.MINIMUM_DERIVED_KEY_LENGTH, key.length);
    }

    @Test
    public void preservesDefaultDerivedKeyLength() throws Exception {
        byte[] key = DerivedKeyUtils.deriveKey(
            ConversationConstants.DerivationAlgorithm.P_SHA_1,
            null,
            0,
            SECRET,
            NONCE,
            0);

        assertEquals(32, key.length);
    }

    @Test
    public void rejectsDerivedKeyLengthAboveMaximum() throws Exception {
        try {
            DerivedKeyUtils.deriveKey(
                ConversationConstants.DerivationAlgorithm.P_SHA_1,
                null,
                DerivedKeyUtils.MAXIMUM_DERIVED_KEY_LENGTH + 1,
                SECRET,
                NONCE,
                0);
            fail("Expected failure on a derived key length above the maximum");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    @Test
    public void rejectsDerivedKeyOffsetOutsideMaximum() throws Exception {
        try {
            DerivedKeyUtils.deriveKey(
                ConversationConstants.DerivationAlgorithm.P_SHA_1,
                null,
                DerivedKeyUtils.MINIMUM_DERIVED_KEY_LENGTH,
                SECRET,
                NONCE,
                DerivedKeyUtils.MAXIMUM_DERIVED_KEY_OFFSET + 1);
            fail("Expected failure on a derived key offset above the maximum");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    @Test
    public void rejectsNegativeDerivedKeyOffset() throws Exception {
        try {
            DerivedKeyUtils.deriveKey(
                ConversationConstants.DerivationAlgorithm.P_SHA_1,
                null,
                DerivedKeyUtils.MINIMUM_DERIVED_KEY_LENGTH,
                SECRET,
                NONCE,
                -1);
            fail("Expected failure on a negative derived key offset");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    @Test
    public void acceptsNonDefaultDerivedKeyLengthAndOffset() throws Exception {
        byte[] key = DerivedKeyUtils.deriveKey(
            ConversationConstants.DerivationAlgorithm.P_SHA_1,
            null,
            24,
            SECRET,
            NONCE,
            32);
        byte[] keyWithDefaultOffset = DerivedKeyUtils.deriveKey(
            ConversationConstants.DerivationAlgorithm.P_SHA_1,
            null,
            24,
            SECRET,
            NONCE,
            0);

        assertEquals(24, key.length);
        assertFalse(java.util.Arrays.equals(keyWithDefaultOffset, key));
    }
}
