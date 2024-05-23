/*
 * This file is part of the CVSS Calculator.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.springett.cvss;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import static us.springett.cvss.CvssFromVectorTest.FailureExpectation.expectFailure;
import static us.springett.cvss.CvssFromVectorTest.SuccessExpectation.expectSuccess;

@RunWith(Parameterized.class)
public class CvssFromVectorTest {

    @Parameters(name = "{index}: vector={0} expectation={1}")
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                // Invalid empty vector
                {"", expectFailure().withMessage("Vector must not be null or empty")},
                // ---
                // CVSSv2
                // ---
                // Valid CVSSv2 vector without parentheses
                {"AV:N/AC:H/Au:N/C:P/I:N/A:N", expectSuccess().withClass(CvssV2.class)},
                // Valid CVSSv2 vector without opening parenthesis
                {"AV:N/AC:H/Au:N/C:P/I:N/A:N)", expectSuccess().withClass(CvssV2.class)},
                // Valid CVSSv2 vector without closing parenthesis
                {"(AV:N/AC:H/Au:N/C:P/I:N/A:N", expectSuccess().withClass(CvssV2.class)},
                // Valid CVSSv2 vector with parentheses
                {"(AV:N/AC:H/Au:N/C:P/I:N/A:N)", expectSuccess().withClass(CvssV2.class)},
                // Valid CVSSv2 vector with temporal metrics
                {"(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:POC/RL:ND/RC:UC)", expectSuccess().withClass(CvssV2.class)},
                // Valid CVSSv2 vector with environmental metrics
                {"(AV:N/AC:H/Au:N/C:P/I:N/A:N/CDP:N/TD:L/CR:M/IR:H/AR:L)", expectSuccess().withClass(CvssV2.class)},
                // Valid CVSSv2 vector with temporal and environmental metrics
                {"(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:POC/RL:ND/RC:UC/CDP:N/TD:L/CR:M/IR:H/AR:L)", expectSuccess().withClass(CvssV2.class)},
                // Non-strict ordering of metrics; Ordering is not enforced
                {"(AC:H/AV:N/Au:N/C:P/I:N/A:N)", expectSuccess().withClass(CvssV2.class)},
                // Invalid CVSSv2 vector with missing segments
                {"(AV:N/AC:H/Au:N/C:P/I:N)", expectFailure().withMessage("Vector must consist of at least 6 segments (mandatory metrics AV, AC, Au, C, I, A), but has only 5")},
                // Invalid CVSSv2 vector with missing mandatory metric
                {"(AV:N/AC:H/Au:N/C:P/I:N/E:POC)", expectFailure().withMessage("Missing mandatory metrics: A")},
                // Invalid CVSSv2 vector with unknown metric
                {"(AV:N/AC:H/Au:N/C:P/I:N/X:X)", expectFailure().withMessage("Unknown metric: X")},
                // Invalid CVSSv2 vector with malformed segment
                {"(AV:N/AC:H/Au:N/C:P/I:N/A:N/foobar)", expectFailure().withMessage("Segment #7 is malformed; Expected format <METRIC>:<VALUE>, but got \"foobar\"")},
                // Invalid CVSSv2 vector with invalid metric value
                {"(AV:N/AC:H/Au:Z/C:P/I:N/A:N)", expectFailure().withMessage("Invalid value for metric Au: Z")},
                // ---
                // CVSSv3.0
                // ---
                // Valid CVSSv3.0 vector with base metrics
                {"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", expectSuccess().withClass(CvssV3.class)},
                // Valid CVSSv3.0 vector with temporal metrics
                {"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:T/RC:C", expectSuccess().withClass(CvssV3.class)},
                // Valid CVSSv3.0 vector with environmental metrics
                {"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:M/AR:M/MAV:A/MAC:H/MPR:N/MUI:R/MS:U/MI:H/MA:L", expectSuccess().withClass(CvssV3.class)},
                // Valid CVSSv3.0 vector with temporal and environmental metrics
                {"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:T/RC:C/CR:L/IR:M/AR:M/MAV:A/MAC:H/MPR:N/MUI:R/MS:U/MI:H/MA:L", expectSuccess().withClass(CvssV3.class)},
                // Non-strict ordering of metrics; Ordering must not be enforced for CVSSv3
                {"CVSS:3.0/AC:H/AV:N/A:H/C:H/I:H/PR:N/S:U/UI:N", expectSuccess().withClass(CvssV3.class)},
                // Invalid CVSSv3.0 vector with missing segments
                {"CVSS:3.0/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", expectFailure().withMessage("Vector must consist of at least 9 segments (CVSS:3.0 prefix and mandatory metrics AV, AC, PR, UI, S, C, I, A), but has only 8")},
                // Invalid CVSSv3.0 vector with missing mandatory metric
                {"CVSS:3.0/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:U", expectFailure().withMessage("Missing mandatory metrics: AV")},
                // Invalid CVSSv3.0 vector with unknown metric
                {"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/X:X", expectFailure().withMessage("Unknown metric: X")},
                // Invalid CVSSv3.0 vector with malformed segment
                {"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/foobar", expectFailure().withMessage("Segment #10 is malformed; Expected format <METRIC>:<VALUE>, but got \"foobar\"")},
                // Invalid CVSSv3.0 vector with invalid metric value
                {"CVSS:3.0/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H", expectFailure().withMessage("Invalid value for metric PR: X")},
                // ---
                // CVSSv3.1
                // ---
                {"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", expectSuccess().withClass(CvssV3_1.class)},
                // Valid CVSSv3.1 vector with temporal metrics
                {"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:T/RC:C", expectSuccess().withClass(CvssV3_1.class)},
                // Valid CVSSv3.1 vector with environmental metrics
                {"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:M/AR:M/MAV:A/MAC:H/MPR:N/MUI:R/MS:U/MI:H/MA:L", expectSuccess().withClass(CvssV3_1.class)},
                // Valid CVSSv3.1 vector with temporal and environmental metrics
                {"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:T/RC:C/CR:L/IR:M/AR:M/MAV:A/MAC:H/MPR:N/MUI:R/MS:U/MI:H/MA:L", expectSuccess().withClass(CvssV3_1.class)},
                // Non-strict ordering of metrics; Ordering must not be enforced for CVSSv3.1
                {"CVSS:3.1/AC:H/AV:N/A:H/C:H/I:H/PR:N/S:U/UI:N", expectSuccess().withClass(CvssV3_1.class)},
                // Invalid CVSSv3.1 vector with missing segments
                {"CVSS:3.1/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", expectFailure().withMessage("Vector must consist of at least 9 segments (CVSS:3.1 prefix and mandatory metrics AV, AC, PR, UI, S, C, I, A), but has only 8")},
                // Invalid CVSSv3.1 vector with missing mandatory metric
                {"CVSS:3.1/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:U", expectFailure().withMessage("Missing mandatory metrics: AV")},
                // Invalid CVSSv3.1 vector with unknown metric
                {"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/X:X", expectFailure().withMessage("Unknown metric: X")},
                // Invalid CVSSv3.1 vector with malformed segment
                {"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/foobar", expectFailure().withMessage("Segment #10 is malformed; Expected format <METRIC>:<VALUE>, but got \"foobar\"")},
                // Invalid CVSSv3.1 vector with invalid metric value
                {"CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H", expectFailure().withMessage("Invalid value for metric PR: X")},

        });
    }

    public interface Expectation {

        void evaluate(String vector);

    }

    static final class SuccessExpectation implements Expectation {

        private Class<? extends Cvss> cvssClass;

        static SuccessExpectation expectSuccess() {
            return new SuccessExpectation();
        }

        private SuccessExpectation withClass(final Class<? extends Cvss> cvssClass) {
            this.cvssClass = cvssClass;
            return this;
        }

        @Override
        public void evaluate(final String vector) {
            final Cvss cvss;
            try {
                cvss = Cvss.fromVector(vector);
            } catch (RuntimeException e) {
                Assert.fail("Expected parsing to not fail, but it failed with: " + e.getMessage());
                return;
            }

            if (cvssClass != null) {
                Assert.assertEquals(cvssClass, cvss.getClass());
            }

            try {
                // Sanity check; Calculation should never fail when parsing succeeded.
                cvss.calculateScore();
            } catch (RuntimeException e) {
                Assert.fail("Expected #calculateScore to not fail, but it failed with: " + e.getMessage());
            }

            try {
                // Sanity check; Vector construction should never fail when parsing succeeded.
                cvss.getVector();
            } catch (RuntimeException e) {
                Assert.fail("Expected #getVector invocation to not fail, but it failed with: " + e.getMessage());
            }
        }

        @Override
        public String toString() {
            return "Success";
        }

    }

    static final class FailureExpectation implements Expectation {

        private String message;

        static FailureExpectation expectFailure() {
            return new FailureExpectation();
        }

        private FailureExpectation withMessage(final String message) {
            this.message = message;
            return this;
        }

        @Override
        public void evaluate(final String vector) {
            RuntimeException exception = null;
            try {
                Cvss.fromVector(vector);
            } catch (RuntimeException e) {
                exception = e;
            }

            Assert.assertNotNull("Expected parsing to fail, but it did not", exception);
            Assert.assertEquals(MalformedVectorException.class, exception.getClass());

            if (message != null) {
                Assert.assertEquals(message, exception.getMessage());
            }
        }

        @Override
        public String toString() {
            return "Failure";
        }

    }

    private final String vector;
    private final Expectation expectation;

    public CvssFromVectorTest(final String vector, final Expectation expectation) {
        this.vector = vector;
        this.expectation = expectation;
    }

    @Test
    public void test() {
        expectation.evaluate(vector);
    }

}
