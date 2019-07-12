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

public class CvssV3Test {

    private CvssV3 cvssV3;

    @Before
    public void setup() {
        cvssV3 = new CvssV3()
                .attackVector(CvssV3.AttackVector.NETWORK)
                .attackComplexity(CvssV3.AttackComplexity.LOW)
                .privilegesRequired(CvssV3.PrivilegesRequired.HIGH)
                .userInteraction(CvssV3.UserInteraction.NONE)
                .scope(CvssV3.Scope.UNCHANGED)
                .confidentiality(CvssV3.CIA.HIGH)
                .integrity(CvssV3.CIA.HIGH)
                .availability(CvssV3.CIA.HIGH);
    }

    @Test
    public void attackVectorTest() {
        cvssV3.attackVector(CvssV3.AttackVector.NETWORK);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());

        cvssV3.attackVector(CvssV3.AttackVector.ADJACENT);
        score = cvssV3.calculateScore();
        Assert.assertEquals(6.8, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(0.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());

        cvssV3.attackVector(CvssV3.AttackVector.LOCAL);
        score = cvssV3.calculateScore();
        Assert.assertEquals(6.7, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(0.8, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());

        cvssV3.attackVector(CvssV3.AttackVector.PHYSICAL);
        score = cvssV3.calculateScore();
        Assert.assertEquals(6.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(0.3, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());
    }

    @Test
    public void attackComplexityTest() {
        cvssV3.attackComplexity(CvssV3.AttackComplexity.LOW);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());

        cvssV3.attackComplexity(CvssV3.AttackComplexity.HIGH);
        score = cvssV3.calculateScore();
        Assert.assertEquals(6.6, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(0.7, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());
    }

    @Test
    public void privilegesRequiredTest() {
        cvssV3.privilegesRequired(CvssV3.PrivilegesRequired.NONE);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(9.8, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());

        cvssV3.privilegesRequired(CvssV3.PrivilegesRequired.LOW);
        score = cvssV3.calculateScore();
        Assert.assertEquals(8.8, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(2.8, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());

        cvssV3.privilegesRequired(CvssV3.PrivilegesRequired.HIGH);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());
    }

    @Test
    public void userInteractionTest() {
        cvssV3.userInteraction(CvssV3.UserInteraction.NONE);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());

        cvssV3.userInteraction(CvssV3.UserInteraction.REQUIRED);
        score = cvssV3.calculateScore();
        Assert.assertEquals(6.8, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(0.9, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H", cvssV3.getVector());
    }

    @Test
    public void scopeTest() {
        cvssV3.scope(CvssV3.Scope.UNCHANGED);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());

        cvssV3.scope(CvssV3.Scope.CHANGED);
        score = cvssV3.calculateScore();
        Assert.assertEquals(9.1, score.getBaseScore(), 0);
        Assert.assertEquals(6.0, score.getImpactSubScore(), 0);
        Assert.assertEquals(2.3, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", cvssV3.getVector());
    }

    @Test
    public void confidentialityTest() {
        cvssV3.confidentiality(CvssV3.CIA.NONE);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(6.5, score.getBaseScore(), 0);
        Assert.assertEquals(5.2, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", cvssV3.getVector());

        cvssV3.confidentiality(CvssV3.CIA.LOW);
        score = cvssV3.calculateScore();
        Assert.assertEquals(6.7, score.getBaseScore(), 0);
        Assert.assertEquals(5.5, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:H", cvssV3.getVector());

        cvssV3.confidentiality(CvssV3.CIA.HIGH);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());
    }

    @Test
    public void integrityTest() {
        cvssV3.integrity(CvssV3.CIA.NONE);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(6.5, score.getBaseScore(), 0);
        Assert.assertEquals(5.2, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H", cvssV3.getVector());

        cvssV3.integrity(CvssV3.CIA.LOW);
        score = cvssV3.calculateScore();
        Assert.assertEquals(6.7, score.getBaseScore(), 0);
        Assert.assertEquals(5.5, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:H", cvssV3.getVector());

        cvssV3.integrity(CvssV3.CIA.HIGH);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());
    }

    @Test
    public void availabilityTest() {
        cvssV3.availability(CvssV3.CIA.NONE);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(6.5, score.getBaseScore(), 0);
        Assert.assertEquals(5.2, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N", cvssV3.getVector());

        cvssV3.availability(CvssV3.CIA.LOW);
        score = cvssV3.calculateScore();
        Assert.assertEquals(6.7, score.getBaseScore(), 0);
        Assert.assertEquals(5.5, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L", cvssV3.getVector());

        cvssV3.availability(CvssV3.CIA.HIGH);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cvssV3.getVector());
    }


    @Test
    public void temporalExploitabilityTest() {
        cvssV3.exploitability(CvssV3.Exploitability.NOT_DEFINED);
        cvssV3.remediationLevel(CvssV3.RemediationLevel.NOT_DEFINED);
        cvssV3.reportConfidence(CvssV3.ReportConfidence.NOT_DEFINED);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(7.2, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X", cvssV3.getVector());

        cvssV3.exploitability(CvssV3.Exploitability.UNPROVEN);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(6.6, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:U/RL:X/RC:X", cvssV3.getVector());

        cvssV3.exploitability(CvssV3.Exploitability.POC);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(6.8, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:P/RL:X/RC:X", cvssV3.getVector());

        cvssV3.exploitability(CvssV3.Exploitability.FUNCTIONAL);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(7.0, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:F/RL:X/RC:X", cvssV3.getVector());

        cvssV3.exploitability(CvssV3.Exploitability.HIGH);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(7.2, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:H/RL:X/RC:X", cvssV3.getVector());
    }

    @Test
    public void temporalRemediationLevelTest() {
        cvssV3.exploitability(CvssV3.Exploitability.NOT_DEFINED);
        cvssV3.reportConfidence(CvssV3.ReportConfidence.NOT_DEFINED);

        cvssV3.remediationLevel(CvssV3.RemediationLevel.OFFICIAL);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(6.9, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:O/RC:X", cvssV3.getVector());

        cvssV3.remediationLevel(CvssV3.RemediationLevel.TEMPORARY);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(7.0, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:T/RC:X", cvssV3.getVector());

        cvssV3.remediationLevel(CvssV3.RemediationLevel.WORKAROUND);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(7.0, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:W/RC:X", cvssV3.getVector());

        cvssV3.remediationLevel(CvssV3.RemediationLevel.UNAVAILABLE);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(7.2, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:U/RC:X", cvssV3.getVector());
    }

    @Test
    public void temporalReportConfidenceTest() {
        cvssV3.exploitability(CvssV3.Exploitability.NOT_DEFINED);
        cvssV3.remediationLevel(CvssV3.RemediationLevel.NOT_DEFINED);

        cvssV3.reportConfidence(CvssV3.ReportConfidence.UNKNOWN);
        Score score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(6.7, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:U", cvssV3.getVector());

        cvssV3.reportConfidence(CvssV3.ReportConfidence.REASONABLE);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(7.0, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:R", cvssV3.getVector());

        cvssV3.reportConfidence(CvssV3.ReportConfidence.CONFIRMED);
        score = cvssV3.calculateScore();
        Assert.assertEquals(7.2, score.getBaseScore(), 0);
        Assert.assertEquals(5.9, score.getImpactSubScore(), 0);
        Assert.assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        Assert.assertEquals(7.2, score.getTemporalScore(), 0);
        Assert.assertEquals(null, "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:C", cvssV3.getVector());
    }
}
