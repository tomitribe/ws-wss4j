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
package org.apache.wss4j.common.crypto;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.Assert;
import org.junit.Test;

/**
 * Tests for the bounds handling of DERDecoder. A DER length is attacker-controlled wherever the
 * decoder is pointed at a certificate extension, so an over-long or non-minimal length must be
 * rejected rather than acted upon.
 */
public class DERDecoderTest extends Assert {

    /**
     * A declared length of Integer.MAX_VALUE from an eleven byte input. The bounds check must not
     * be computed as "pos + length", which overflows to a negative number and lets the decoder
     * through to a two gigabyte allocation.
     */
    @Test
    public void testGetBytesRejectsLengthThatWouldOverflowThePosition() throws Exception {
        // 04 09 | 04 84 7FFFFFFF | 01 02 03 -- the shape CryptoBase.getSKIBytesFromCert decodes
        byte[] extension = {4, 9, 4, (byte)0x84, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 1, 2, 3};

        final DERDecoder decoder = new DERDecoder(extension);
        decoder.expect(DERDecoder.TYPE_OCTET_STRING);
        decoder.getLength();
        decoder.expect(DERDecoder.TYPE_OCTET_STRING);
        final int keyIdentifierLength = decoder.getLength();
        assertEquals(Integer.MAX_VALUE, keyIdentifierLength);

        assertRejected(new DerCall() {
            public void call() throws Exception {
                decoder.getBytes(keyIdentifierLength);
            }
        });
    }

    @Test
    public void testGetBytesRejectsLengthBeyondTheRemainingInput() throws Exception {
        final DERDecoder decoder = new DERDecoder(new byte[] {1, 2, 3, 4});
        decoder.skip(2);

        assertArrayEquals(new byte[] {3, 4}, new DERDecoder(new byte[] {3, 4}).getBytes(2));
        assertRejected(new DerCall() {
            public void call() throws Exception {
                decoder.getBytes(3);
            }
        });
    }

    @Test
    public void testGetBytesRejectsNegativeLength() throws Exception {
        final DERDecoder decoder = new DERDecoder(new byte[] {1, 2, 3, 4});

        assertRejected(new DerCall() {
            public void call() throws Exception {
                decoder.getBytes(-1);
            }
        });
    }

    /**
     * Skipping past the end must fail rather than leave the position out of bounds, where a large
     * enough length would wrap it negative and turn a later read into an ArrayIndexOutOfBounds.
     */
    @Test
    public void testSkipRejectsLengthBeyondTheRemainingInput() throws Exception {
        final DERDecoder decoder = new DERDecoder(new byte[] {1, 2, 3, 4});
        decoder.skip(4);
        assertRejected(new DerCall() {
            public void call() throws Exception {
                decoder.skip(1);
            }
        });

        final DERDecoder overflowing = new DERDecoder(new byte[] {1, 2, 3, 4});
        overflowing.skip(2);
        assertRejected(new DerCall() {
            public void call() throws Exception {
                overflowing.skip(Integer.MAX_VALUE);
            }
        });
    }

    @Test
    public void testGetLengthReadsShortAndLongForm() throws Exception {
        assertEquals(0, new DERDecoder(new byte[] {0}).getLength());
        assertEquals(127, new DERDecoder(new byte[] {0x7F}).getLength());
        assertEquals(128, new DERDecoder(new byte[] {(byte)0x81, (byte)0x80}).getLength());
        assertEquals(256, new DERDecoder(new byte[] {(byte)0x82, 1, 0}).getLength());
        assertEquals(Integer.MAX_VALUE,
            new DERDecoder(new byte[] {(byte)0x84, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF}).getLength());
    }

    /**
     * Indefinite length is reported as -1, as the method contract has always stated. Every caller
     * feeds the result to getBytes or skip, both of which reject a negative length.
     */
    @Test
    public void testGetLengthReportsIndefiniteLengthAsMinusOne() throws Exception {
        assertEquals(-1, new DERDecoder(new byte[] {(byte)0x80, 0, 0}).getLength());

        final DERDecoder decoder = new DERDecoder(new byte[] {(byte)0x80, 0, 0});
        final int length = decoder.getLength();
        assertRejected(new DerCall() {
            public void call() throws Exception {
                decoder.getBytes(length);
            }
        });
    }

    /**
     * DER requires the shortest possible length encoding, so a long form that could have been
     * short, or one carrying a leading zero, is invalid.
     */
    @Test
    public void testGetLengthRejectsNonMinimalEncodings() {
        assertLengthRejected(new byte[] {(byte)0x81, 0x7F});
        assertLengthRejected(new byte[] {(byte)0x82, 0, (byte)0x80});
        assertLengthRejected(new byte[] {(byte)0x83, 0, 1, 0});
    }

    @Test
    public void testGetLengthRejectsLengthsThatDoNotFitInAnInt() {
        // 0x80000000 is one past Integer.MAX_VALUE
        assertLengthRejected(new byte[] {(byte)0x84, (byte)0x80, 0, 0, 0});
        assertLengthRejected(new byte[] {(byte)0x84, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF});
        // more length bytes than an int can hold
        assertLengthRejected(new byte[] {(byte)0x85, 1, 0, 0, 0, 0});
    }

    @Test
    public void testGetLengthRejectsTruncatedLengthSpecification() {
        assertLengthRejected(new byte[0]);
        assertLengthRejected(new byte[] {(byte)0x82, 1});
    }

    @Test
    public void testExpectEnd() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {4, 1, 9});
        decoder.expect(DERDecoder.TYPE_OCTET_STRING);
        decoder.getBytes(decoder.getLength());
        decoder.expectEnd();

        final DERDecoder trailing = new DERDecoder(new byte[] {4, 1, 9, 0});
        trailing.expect(DERDecoder.TYPE_OCTET_STRING);
        trailing.getBytes(trailing.getLength());
        assertRejected(new DerCall() {
            public void call() throws Exception {
                trailing.expectEnd();
            }
        });
    }

    @Test
    public void testHasRemaining() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {1, 2});
        decoder.skip(1);
        assertEquals(true, decoder.hasRemaining());
        decoder.skip(1);
        assertEquals(false, decoder.hasRemaining());

        assertEquals(false, new DERDecoder(new byte[0]).hasRemaining());
    }

    private interface DerCall {
        void call() throws Exception;
    }

    private static void assertLengthRejected(final byte[] encoded) {
        assertRejected(new DerCall() {
            public void call() throws Exception {
                new DERDecoder(encoded).getLength();
            }
        });
    }

    private static void assertRejected(DerCall call) {
        try {
            call.call();
        } catch (WSSecurityException expected) {
            return;
        } catch (Exception ex) {
            fail("Expected a WSSecurityException, but got " + ex);
        }
        fail("Expected a WSSecurityException");
    }
}
