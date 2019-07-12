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
import org.junit.Before;
import org.junit.Test;

public class CvssV2Test {

    private CvssV2 cvssV2;
    private CvssV2 cvssV2Temporal;

    @Before
    public void setup() {
        cvssV2 = new CvssV2()
                .attackVector(CvssV2.AttackVector.NETWORK)
                .attackComplexity(CvssV2.AttackComplexity.MEDIUM)
                .authentication(CvssV2.Authentication.NONE)
                .confidentiality(CvssV2.CIA.PARTIAL)
                .integrity(CvssV2.CIA.PARTIAL)
                .availability(CvssV2.CIA.PARTIAL);

        cvssV2Temporal = new CvssV2()
                .attackVector(CvssV2.AttackVector.NETWORK)
                .attackComplexity(CvssV2.AttackComplexity.HIGH)
                .authentication(CvssV2.Authentication.NONE)
                .confidentiality(CvssV2.CIA.PARTIAL)
                .integrity(CvssV2.CIA.NONE)
                .availability(CvssV2.CIA.NONE)
                .exploitability(CvssV2.Exploitability.FUNCTIONAL)
                .remediationLevel(CvssV2.RemediationLevel.WORKAROUND)
                .reportConfidence(CvssV2.ReportConfidence.CONFIRMED);
    }

    @Test
    public void attackVectorTest() {
        cvssV2.attackVector(CvssV2.AttackVector.NETWORK);
        Score score = cvssV2.calculateScore();
        Assert.assertEquals(6.8, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.attackVector(CvssV2.AttackVector.ADJACENT);
        score = cvssV2.calculateScore();
        Assert.assertEquals(5.4, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(5.5, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:A/AC:M/Au:N/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.attackVector(CvssV2.AttackVector.LOCAL);
        score = cvssV2.calculateScore();
        Assert.assertEquals(4.4, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(3.4, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:L/AC:M/Au:N/C:P/I:P/A:P)", cvssV2.getVector());
    }

    @Test
    public void attackComplexityTest() {
        cvssV2.attackComplexity(CvssV2.AttackComplexity.LOW);
        Score score = cvssV2.calculateScore();
        Assert.assertEquals(7.5, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(10.0, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:L/Au:N/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.attackComplexity(CvssV2.AttackComplexity.MEDIUM);
        score = cvssV2.calculateScore();
        Assert.assertEquals(6.8, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.attackComplexity(CvssV2.AttackComplexity.HIGH);
        score = cvssV2.calculateScore();
        Assert.assertEquals(5.1, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:P/A:P)", cvssV2.getVector());
    }

    @Test
    public void authenticationTest() {
        cvssV2.authentication(CvssV2.Authentication.NONE);
        Score score = cvssV2.calculateScore();
        Assert.assertEquals(6.8, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.authentication(CvssV2.Authentication.SINGLE);
        score = cvssV2.calculateScore();
        Assert.assertEquals(6.0, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(6.8, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:S/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.authentication(CvssV2.Authentication.MULTIPLE);
        score = cvssV2.calculateScore();
        Assert.assertEquals(5.4, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(5.5, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:M/C:P/I:P/A:P)", cvssV2.getVector());
    }

    @Test
    public void confidentialityTest() {
        cvssV2.confidentiality(CvssV2.CIA.NONE);
        Score score = cvssV2.calculateScore();
        Assert.assertEquals(5.8, score.getBaseScore(), 0);
        Assert.assertEquals(4.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:N/I:P/A:P)", cvssV2.getVector());

        cvssV2.confidentiality(CvssV2.CIA.PARTIAL);
        score = cvssV2.calculateScore();
        Assert.assertEquals(6.8, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.confidentiality(CvssV2.CIA.COMPLETE);
        score = cvssV2.calculateScore();
        Assert.assertEquals(8.3, score.getBaseScore(), 0);
        Assert.assertEquals(8.5, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:C/I:P/A:P)", cvssV2.getVector());
    }

    @Test
    public void integrityTest() {
        cvssV2.integrity(CvssV2.CIA.NONE);
        Score score = cvssV2.calculateScore();
        Assert.assertEquals(5.8, score.getBaseScore(), 0);
        Assert.assertEquals(4.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:N/A:P)", cvssV2.getVector());

        cvssV2.integrity(CvssV2.CIA.PARTIAL);
        score = cvssV2.calculateScore();
        Assert.assertEquals(6.8, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.integrity(CvssV2.CIA.COMPLETE);
        score = cvssV2.calculateScore();
        Assert.assertEquals(8.3, score.getBaseScore(), 0);
        Assert.assertEquals(8.5, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:C/A:P)", cvssV2.getVector());
    }

    @Test
    public void availabilityTest() {
        cvssV2.availability(CvssV2.CIA.NONE);
        Score score = cvssV2.calculateScore();
        Assert.assertEquals(5.8, score.getBaseScore(), 0);
        Assert.assertEquals(4.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:P/A:N)", cvssV2.getVector());

        cvssV2.availability(CvssV2.CIA.PARTIAL);
        score = cvssV2.calculateScore();
        Assert.assertEquals(6.8, score.getBaseScore(), 0);
        Assert.assertEquals(6.4, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:P/A:P)", cvssV2.getVector());

        cvssV2.availability(CvssV2.CIA.COMPLETE);
        score = cvssV2.calculateScore();
        Assert.assertEquals(8.3, score.getBaseScore(), 0);
        Assert.assertEquals(8.5, score.getImpactSubScore(), 0);
        Assert.assertEquals(8.6, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:M/Au:N/C:P/I:P/A:C)", cvssV2.getVector());
    }

    @Test
    public void temporalTestExploitability() {
        Score score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.3, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:W/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.exploitability(CvssV2.Exploitability.HIGH);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.5, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:H/RL:W/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.exploitability(CvssV2.Exploitability.UNPROVEN);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.1, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:U/RL:W/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.exploitability(CvssV2.Exploitability.POC);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.2, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:POC/RL:W/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.exploitability(CvssV2.Exploitability.NOT_DEFINED);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.5, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:ND/RL:W/RC:C)", cvssV2Temporal.getVector());
    }

    @Test
    public void temporalTestRemediation() {
        Score score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.3, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:W/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.remediationLevel(CvssV2.RemediationLevel.UNAVAILABLE);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.5, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:U/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.remediationLevel(CvssV2.RemediationLevel.TEMPORARY);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.2, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:TF/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.remediationLevel(CvssV2.RemediationLevel.OFFICIAL);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.1, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:OF/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.remediationLevel(CvssV2.RemediationLevel.NOT_DEFINED);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.5, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:ND/RC:C)", cvssV2Temporal.getVector());
    }

    @Test
    public void temporalTestReportConfidence() {
        Score score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.3, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:W/RC:C)", cvssV2Temporal.getVector());

        cvssV2Temporal.reportConfidence(CvssV2.ReportConfidence.UNCORROBORATED);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.2, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:W/RC:UR)", cvssV2Temporal.getVector());

        cvssV2Temporal.reportConfidence(CvssV2.ReportConfidence.UNCONFIRMED);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.1, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:W/RC:UC)", cvssV2Temporal.getVector());

        cvssV2Temporal.reportConfidence(CvssV2.ReportConfidence.NOT_DEFINED);
        score = cvssV2Temporal.calculateScore();
        Assert.assertEquals(2.6, score.getBaseScore(), 0);
        Assert.assertEquals(2.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(4.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(2.3, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "(AV:N/AC:H/Au:N/C:P/I:N/A:N/E:F/RL:W/RC:ND)", cvssV2Temporal.getVector());
    }
}
