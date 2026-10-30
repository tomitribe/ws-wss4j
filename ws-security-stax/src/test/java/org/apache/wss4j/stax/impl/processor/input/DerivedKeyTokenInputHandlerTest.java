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
package org.apache.wss4j.stax.impl.processor.input;

import java.math.BigInteger;

import org.apache.wss4j.common.derivedKey.DerivedKeyUtils;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.Assert;
import org.junit.Test;

/**
 * The wsc:Length and wsc:Offset of a DerivedKeyToken are attacker-controlled xs:unsignedLong
 * values. They must be range checked before they are narrowed to an int, otherwise a missing
 * value fails with a NullPointerException and an oversized one silently wraps around (e.g.
 * 2^32 + 16 becomes 16) and slips past the bounds that DerivedKeyUtils enforces.
 */
public class DerivedKeyTokenInputHandlerTest extends Assert {

    private static final int MAX_LENGTH = DerivedKeyUtils.MAXIMUM_DERIVED_KEY_LENGTH;
    private static final int MAX_OFFSET = DerivedKeyUtils.MAXIMUM_DERIVED_KEY_OFFSET;

    @Test
    public void testValuesInRangeAreReturned() throws Exception {
        assertEquals(0, DerivedKeyTokenInputHandler.getDerivedKeyParameter(BigInteger.ZERO, MAX_LENGTH, "length"));
        assertEquals(32, DerivedKeyTokenInputHandler.getDerivedKeyParameter(BigInteger.valueOf(32), MAX_LENGTH, "length"));
        assertEquals(MAX_LENGTH,
            DerivedKeyTokenInputHandler.getDerivedKeyParameter(BigInteger.valueOf(MAX_LENGTH), MAX_LENGTH, "length"));
        assertEquals(MAX_OFFSET,
            DerivedKeyTokenInputHandler.getDerivedKeyParameter(BigInteger.valueOf(MAX_OFFSET), MAX_OFFSET, "offset"));
    }

    @Test
    public void testMissingValueIsRejected() throws Exception {
        assertRejected(null, MAX_LENGTH, "length");
        assertRejected(null, MAX_OFFSET, "offset");
    }

    @Test
    public void testNegativeValueIsRejected() throws Exception {
        assertRejected(BigInteger.valueOf(-1), MAX_LENGTH, "length");
        assertRejected(BigInteger.valueOf(-1), MAX_OFFSET, "offset");
    }

    @Test
    public void testValueAboveMaximumIsRejected() throws Exception {
        assertRejected(BigInteger.valueOf(MAX_LENGTH + 1L), MAX_LENGTH, "length");
        assertRejected(BigInteger.valueOf(MAX_OFFSET + 1L), MAX_OFFSET, "offset");
        assertRejected(BigInteger.valueOf(Integer.MAX_VALUE), MAX_LENGTH, "length");
    }

    @Test
    public void testValueThatWouldWrapAroundIsRejected() throws Exception {
        // 2^32 + 16: BigInteger.intValue() yields 16, which would pass every int-based bound
        BigInteger wrapsToSixteen = BigInteger.ONE.shiftLeft(32).add(BigInteger.valueOf(16));
        assertEquals(16, wrapsToSixteen.intValue());
        assertRejected(wrapsToSixteen, MAX_LENGTH, "length");
        assertRejected(wrapsToSixteen, MAX_OFFSET, "offset");

        // The largest xs:unsignedLong; intValue() yields -1
        BigInteger maxUnsignedLong = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        assertRejected(maxUnsignedLong, MAX_LENGTH, "length");
        assertRejected(maxUnsignedLong, MAX_OFFSET, "offset");
    }

    private static void assertRejected(BigInteger value, int maximum, String name) {
        try {
            DerivedKeyTokenInputHandler.getDerivedKeyParameter(value, maximum, name);
            fail("Expected derived key " + name + " " + value + " to be rejected");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }
}
