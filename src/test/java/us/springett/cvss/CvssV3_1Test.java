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

import static org.junit.Assert.assertEquals;

public class CvssV3_1Test {

    private CvssV3_1 cvssV3_1;

    @Before
    public void setup() {
        cvssV3_1 = new CvssV3_1()
                /* BASE SCORE */
                .attackVector(CvssV3_1.AttackVector.NETWORK)
                .attackComplexity(CvssV3_1.AttackComplexity.LOW)
                .privilegesRequired(CvssV3_1.PrivilegesRequired.NONE)
                .userInteraction(CvssV3_1.UserInteraction.NONE)
                .scope(CvssV3_1.Scope.UNCHANGED)
                .confidentiality(CvssV3_1.CIA.NONE)
                .integrity(CvssV3_1.CIA.NONE)
                .availability(CvssV3_1.CIA.NONE)

                /* TEMPORAL SCORE */
                .exploitability(CvssV3_1.Exploitability.UNPROVEN)
                .remediationLevel(CvssV3_1.RemediationLevel.OFFICIAL)
                .reportConfidence(CvssV3_1.ReportConfidence.UNKNOWN)

                /* ENVIRONMENTAL SCORE */
                .confidentialityRequirement(CvssV3_1.ConfidentialityRequirement.LOW)
                .integrityRequirement(CvssV3_1.IntegrityRequirement.LOW)
                .availabilityRequirement(CvssV3_1.AvailabilityRequirement.LOW)
                .modifiedAttackVector(CvssV3_1.ModifiedAttackVector.NETWORK)
                .modifiedAttackComplexity(CvssV3_1.ModifiedAttackComplexity.LOW)
                .modifiedPrivilegesRequired(CvssV3_1.ModifiedPrivilegesRequired.NONE)
                .modifiedUserInteraction(CvssV3_1.ModifiedUserInteraction.NONE)
                .modifiedScope(CvssV3_1.ModifiedScope.UNCHANGED)
                .modifiedConfidentialityImpact(CvssV3_1.ModifiedCIA.NONE)
                .modifiedIntegrityImpact(CvssV3_1.ModifiedCIA.NONE)
                .modifiedAvailabilityImpact(CvssV3_1.ModifiedCIA.NONE);
    }

    /* BASE SCORE METRICS */
    @Test
    public void attackVectorTest() {
        cvssV3_1.attackVector(CvssV3_1.AttackVector.NETWORK);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AttackVector.NETWORK, cvssV3_1.getAttackVector());

        cvssV3_1.attackVector(CvssV3_1.AttackVector.ADJACENT);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(2.8, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AttackVector.ADJACENT, cvssV3_1.getAttackVector());

        cvssV3_1.attackVector(CvssV3_1.AttackVector.LOCAL);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(2.5, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AttackVector.LOCAL, cvssV3_1.getAttackVector());

        cvssV3_1.attackVector(CvssV3_1.AttackVector.PHYSICAL);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(0.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AttackVector.PHYSICAL, cvssV3_1.getAttackVector());
    }

    @Test
    public void attackComplexityTest() {
        cvssV3_1.attackComplexity(CvssV3_1.AttackComplexity.LOW);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AttackComplexity.LOW, cvssV3_1.getAttackComplexity());

        cvssV3_1.attackComplexity(CvssV3_1.AttackComplexity.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(2.2, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AttackComplexity.HIGH, cvssV3_1.getAttackComplexity());
    }

    @Test
    public void attackVectorCornerCaseTest() {
        CvssV3_1 cvssV3_test = new CvssV3_1()
                .attackVector(CvssV3_1.AttackVector.PHYSICAL)
                .attackComplexity(CvssV3_1.AttackComplexity.HIGH)
                .privilegesRequired(CvssV3_1.PrivilegesRequired.LOW)
                .userInteraction(CvssV3_1.UserInteraction.REQUIRED)
                .scope(CvssV3_1.Scope.UNCHANGED)
                .confidentiality(CvssV3_1.CIA.LOW)
                .integrity(CvssV3_1.CIA.LOW)
                .availability(CvssV3_1.CIA.HIGH)
                .exploitability(CvssV3_1.Exploitability.HIGH)
                .remediationLevel(CvssV3_1.RemediationLevel.UNAVAILABLE)
                .reportConfidence(CvssV3_1.ReportConfidence.UNKNOWN)
                .confidentialityRequirement(CvssV3_1.ConfidentialityRequirement.LOW)
                .integrityRequirement(CvssV3_1.IntegrityRequirement.MEDIUM)
                .availabilityRequirement(CvssV3_1.AvailabilityRequirement.LOW)
                .modifiedAttackVector(CvssV3_1.ModifiedAttackVector.PHYSICAL)
                .modifiedAttackComplexity(CvssV3_1.ModifiedAttackComplexity.HIGH)
                .modifiedPrivilegesRequired(CvssV3_1.ModifiedPrivilegesRequired.NONE)
                .modifiedUserInteraction(CvssV3_1.ModifiedUserInteraction.REQUIRED)
                .modifiedScope(CvssV3_1.ModifiedScope.UNCHANGED)
                .modifiedConfidentialityImpact(CvssV3_1.ModifiedCIA.LOW)
                .modifiedIntegrityImpact(CvssV3_1.ModifiedCIA.LOW)
                .modifiedAvailabilityImpact(CvssV3_1.ModifiedCIA.LOW);
        Score score = cvssV3_test.calculateScore();
        assertEquals(5.0, score.getBaseScore(), 0);
        assertEquals(4.6, score.getTemporalScore(), 0);
    }

    @Test
    public void privilegesRequiredTest() {
        cvssV3_1.privilegesRequired(CvssV3.PrivilegesRequired.NONE);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3.PrivilegesRequired.NONE, cvssV3_1.getPrivilegesRequired());

        cvssV3_1.privilegesRequired(CvssV3.PrivilegesRequired.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(2.8, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3.PrivilegesRequired.LOW, cvssV3_1.getPrivilegesRequired());

        cvssV3_1.privilegesRequired(CvssV3.PrivilegesRequired.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(1.2, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3.PrivilegesRequired.HIGH, cvssV3_1.getPrivilegesRequired());
    }

    @Test
    public void userInteractionTest() {
        cvssV3_1.userInteraction(CvssV3_1.UserInteraction.NONE);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.UserInteraction.NONE, cvssV3_1.getUserInteraction());

        cvssV3_1.userInteraction(CvssV3_1.UserInteraction.REQUIRED);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(2.8, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.UserInteraction.REQUIRED, cvssV3_1.getUserInteraction());
    }

    @Test
    public void scopeTest() {
        cvssV3_1.scope(CvssV3.Scope.UNCHANGED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3.Scope.UNCHANGED, cvssV3_1.getScope());

        cvssV3_1.scope(CvssV3.Scope.CHANGED);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3.Scope.CHANGED, cvssV3_1.getScope());
    }

    @Test
    public void confidentialityTest() {
        cvssV3_1.confidentiality(CvssV3_1.CIA.NONE);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.NONE, cvssV3_1.getConfidentiality());

        cvssV3_1.confidentiality(CvssV3_1.CIA.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(5.3, score.getBaseScore(), 0);
        assertEquals(1.4, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(4.3, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.LOW, cvssV3_1.getConfidentiality());

        cvssV3_1.confidentiality(CvssV3_1.CIA.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(7.5, score.getBaseScore(), 0);
        assertEquals(3.6, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(6.0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.HIGH, cvssV3_1.getConfidentiality());
    }

    @Test
    public void integrityTest() {
        cvssV3_1.integrity(CvssV3_1.CIA.NONE);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.NONE, cvssV3_1.getIntegrity());

        cvssV3_1.integrity(CvssV3_1.CIA.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(5.3, score.getBaseScore(), 0);
        assertEquals(1.4, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(4.3, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.LOW, cvssV3_1.getIntegrity());

        cvssV3_1.integrity(CvssV3_1.CIA.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(7.5, score.getBaseScore(), 0);
        assertEquals(3.6, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(6.0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.HIGH, cvssV3_1.getIntegrity());
    }

    @Test
    public void availabilityTest() {
        cvssV3_1.availability(CvssV3_1.CIA.NONE);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.NONE, cvssV3_1.getAvailability());

        cvssV3_1.availability(CvssV3_1.CIA.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(5.3, score.getBaseScore(), 0);
        assertEquals(1.4, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(4.3, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.LOW, cvssV3_1.getAvailability());

        cvssV3_1.availability(CvssV3_1.CIA.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(7.5, score.getBaseScore(), 0);
        assertEquals(3.6, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(6.0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.CIA.HIGH, cvssV3_1.getAvailability());
    }

    /* TEMPORAL SCORE METRICS */
    @Test
    public void temporalExploitabilityTest() {
        cvssV3_1.exploitability(CvssV3_1.Exploitability.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:X/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.Exploitability.NOT_DEFINED, cvssV3_1.getExploitability());

        cvssV3_1.exploitability(CvssV3_1.Exploitability.UNPROVEN);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.Exploitability.UNPROVEN, cvssV3_1.getExploitability());

        cvssV3_1.exploitability(CvssV3_1.Exploitability.POC);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:P/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.Exploitability.POC, cvssV3_1.getExploitability());

        cvssV3_1.exploitability(CvssV3_1.Exploitability.FUNCTIONAL);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:F/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.Exploitability.FUNCTIONAL, cvssV3_1.getExploitability());

        cvssV3_1.exploitability(CvssV3_1.Exploitability.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:H/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.Exploitability.HIGH, cvssV3_1.getExploitability());
    }

    @Test
    public void temporalRemediationLevelTest() {
        cvssV3_1.remediationLevel(CvssV3_1.RemediationLevel.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:X/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.RemediationLevel.NOT_DEFINED, cvssV3_1.getRemediationLevel());

        cvssV3_1.remediationLevel(CvssV3_1.RemediationLevel.OFFICIAL);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.RemediationLevel.OFFICIAL, cvssV3_1.getRemediationLevel());

        cvssV3_1.remediationLevel(CvssV3_1.RemediationLevel.TEMPORARY);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:T/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.RemediationLevel.TEMPORARY, cvssV3_1.getRemediationLevel());

        cvssV3_1.remediationLevel(CvssV3_1.RemediationLevel.WORKAROUND);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:W/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.RemediationLevel.WORKAROUND, cvssV3_1.getRemediationLevel());

        cvssV3_1.remediationLevel(CvssV3_1.RemediationLevel.UNAVAILABLE);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:U/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.RemediationLevel.UNAVAILABLE, cvssV3_1.getRemediationLevel());
    }

    @Test
    public void temporalReportConfidenceTest() {
        cvssV3_1.reportConfidence(CvssV3_1.ReportConfidence.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:X/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ReportConfidence.NOT_DEFINED, cvssV3_1.getReportConfidence());

        cvssV3_1.reportConfidence(CvssV3_1.ReportConfidence.UNKNOWN);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ReportConfidence.UNKNOWN, cvssV3_1.getReportConfidence());

        cvssV3_1.reportConfidence(CvssV3_1.ReportConfidence.REASONABLE);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:R/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ReportConfidence.REASONABLE, cvssV3_1.getReportConfidence());

        cvssV3_1.reportConfidence(CvssV3_1.ReportConfidence.CONFIRMED);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:C/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ReportConfidence.CONFIRMED, cvssV3_1.getReportConfidence());
    }

    /* ENVIRONMENTAL SCORE METRICS */
    @Test
    public void confidentialityRequirementTest() {
        cvssV3_1.confidentialityRequirement(CvssV3_1.ConfidentialityRequirement.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:X/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ConfidentialityRequirement.NOT_DEFINED, cvssV3_1.getConfidentialityRequirement());

        cvssV3_1.confidentialityRequirement(CvssV3_1.ConfidentialityRequirement.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ConfidentialityRequirement.LOW, cvssV3_1.getConfidentialityRequirement());

        cvssV3_1.confidentialityRequirement(CvssV3_1.ConfidentialityRequirement.MEDIUM);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:M/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ConfidentialityRequirement.MEDIUM, cvssV3_1.getConfidentialityRequirement());

        cvssV3_1.confidentialityRequirement(CvssV3_1.ConfidentialityRequirement.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:H/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ConfidentialityRequirement.HIGH, cvssV3_1.getConfidentialityRequirement());
    }

    @Test
    public void integrityRequirementTest() {
        cvssV3_1.integrityRequirement(CvssV3_1.IntegrityRequirement.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:X/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.IntegrityRequirement.NOT_DEFINED, cvssV3_1.getIntegrityRequirement());

        cvssV3_1.integrityRequirement(CvssV3_1.IntegrityRequirement.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.IntegrityRequirement.LOW, cvssV3_1.getIntegrityRequirement());

        cvssV3_1.integrityRequirement(CvssV3_1.IntegrityRequirement.MEDIUM);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.IntegrityRequirement.MEDIUM, cvssV3_1.getIntegrityRequirement());

        cvssV3_1.integrityRequirement(CvssV3_1.IntegrityRequirement.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:H/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.IntegrityRequirement.HIGH, cvssV3_1.getIntegrityRequirement());
    }

    @Test
    public void availabilityRequirementTest() {
        cvssV3_1.availabilityRequirement(CvssV3_1.AvailabilityRequirement.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:X/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AvailabilityRequirement.NOT_DEFINED, cvssV3_1.getAvailabilityRequirement());

        cvssV3_1.availabilityRequirement(CvssV3_1.AvailabilityRequirement.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AvailabilityRequirement.LOW, cvssV3_1.getAvailabilityRequirement());

        cvssV3_1.availabilityRequirement(CvssV3_1.AvailabilityRequirement.MEDIUM);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AvailabilityRequirement.MEDIUM, cvssV3_1.getAvailabilityRequirement());

        cvssV3_1.availabilityRequirement(CvssV3_1.AvailabilityRequirement.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.AvailabilityRequirement.HIGH, cvssV3_1.getAvailabilityRequirement());
    }

    @Test
    public void modifiedAttackVectorTest() {
        cvssV3_1.modifiedAttackVector(CvssV3_1.ModifiedAttackVector.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:X/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedAttackVector.NOT_DEFINED, cvssV3_1.getModifiedAttackVector());

        cvssV3_1.modifiedAttackVector(CvssV3_1.ModifiedAttackVector.NETWORK);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedAttackVector.NETWORK, cvssV3_1.getModifiedAttackVector());

        cvssV3_1.modifiedAttackVector(CvssV3_1.ModifiedAttackVector.ADJACENT);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedAttackVector.ADJACENT, cvssV3_1.getModifiedAttackVector());

        cvssV3_1.modifiedAttackVector(CvssV3_1.ModifiedAttackVector.LOCAL);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:L/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedAttackVector.LOCAL, cvssV3_1.getModifiedAttackVector());

        cvssV3_1.modifiedAttackVector(CvssV3_1.ModifiedAttackVector.PHYSICAL);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedAttackVector.PHYSICAL, cvssV3_1.getModifiedAttackVector());
    }

    @Test
    public void modifiedAttackComplexityTest() {
        cvssV3_1.modifiedAttackComplexity(CvssV3_1.ModifiedAttackComplexity.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:X/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedAttackComplexity.NOT_DEFINED, cvssV3_1.getModifiedAttackComplexity());

        cvssV3_1.modifiedAttackComplexity(CvssV3_1.ModifiedAttackComplexity.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedAttackComplexity.LOW, cvssV3_1.getModifiedAttackComplexity());

        cvssV3_1.modifiedAttackComplexity(CvssV3_1.ModifiedAttackComplexity.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:H/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedAttackComplexity.HIGH, cvssV3_1.getModifiedAttackComplexity());
    }

    @Test
    public void modifiedPrivilegesRequiredTest() {
        cvssV3_1.modifiedPrivilegesRequired(CvssV3_1.ModifiedPrivilegesRequired.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:X/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedPrivilegesRequired.NOT_DEFINED, cvssV3_1.getModifiedPrivilegesRequired());

        cvssV3_1.modifiedPrivilegesRequired(CvssV3_1.ModifiedPrivilegesRequired.NONE);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedPrivilegesRequired.NONE, cvssV3_1.getModifiedPrivilegesRequired());

        cvssV3_1.modifiedPrivilegesRequired(CvssV3_1.ModifiedPrivilegesRequired.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:L/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedPrivilegesRequired.LOW, cvssV3_1.getModifiedPrivilegesRequired());

        cvssV3_1.modifiedPrivilegesRequired(CvssV3_1.ModifiedPrivilegesRequired.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedPrivilegesRequired.HIGH, cvssV3_1.getModifiedPrivilegesRequired());
    }

    @Test
    public void modifiedUserInteractionTest() {
        cvssV3_1.modifiedUserInteraction(CvssV3_1.ModifiedUserInteraction.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:X/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedUserInteraction.NOT_DEFINED, cvssV3_1.getModifiedUserInteraction());

        cvssV3_1.modifiedUserInteraction(CvssV3_1.ModifiedUserInteraction.NONE);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedUserInteraction.NONE, cvssV3_1.getModifiedUserInteraction());

        cvssV3_1.modifiedUserInteraction(CvssV3_1.ModifiedUserInteraction.REQUIRED);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:R/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedUserInteraction.REQUIRED, cvssV3_1.getModifiedUserInteraction());
    }

    @Test
    public void modifiedScopeTest() {
        cvssV3_1.modifiedScope(CvssV3_1.ModifiedScope.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:X/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedScope.NOT_DEFINED, cvssV3_1.getModifiedScope());

        cvssV3_1.modifiedScope(CvssV3_1.ModifiedScope.UNCHANGED);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedScope.UNCHANGED, cvssV3_1.getModifiedScope());

        cvssV3_1.modifiedScope(CvssV3_1.ModifiedScope.CHANGED);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedScope.CHANGED, cvssV3_1.getModifiedScope());
    }

    @Test
    public void modifiedConfidentialityImpactTest() {
        cvssV3_1.modifiedConfidentialityImpact(CvssV3_1.ModifiedCIA.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:X/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.NOT_DEFINED, cvssV3_1.getModifiedConfidentialityImpact());

        cvssV3_1.modifiedConfidentialityImpact(CvssV3_1.ModifiedCIA.NONE);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.NONE, cvssV3_1.getModifiedConfidentialityImpact());

        cvssV3_1.modifiedConfidentialityImpact(CvssV3_1.ModifiedCIA.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(3.7, score.getEnvironmentalScore(), 0);
        assertEquals(0.7, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:L/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.LOW, cvssV3_1.getModifiedConfidentialityImpact());

        cvssV3_1.modifiedConfidentialityImpact(CvssV3_1.ModifiedCIA.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(4.6, score.getEnvironmentalScore(), 0);
        assertEquals(1.8, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.HIGH, cvssV3_1.getModifiedConfidentialityImpact());
    }

    @Test
    public void modifiedIntegrityImpactTest() {
        cvssV3_1.modifiedIntegrityImpact(CvssV3_1.ModifiedCIA.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:X/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.NOT_DEFINED, cvssV3_1.getModifiedIntegrityImpact());

        cvssV3_1.modifiedIntegrityImpact(CvssV3_1.ModifiedCIA.NONE);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.NONE, cvssV3_1.getModifiedIntegrityImpact());

        cvssV3_1.modifiedIntegrityImpact(CvssV3_1.ModifiedCIA.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(3.7, score.getEnvironmentalScore(), 0);
        assertEquals(0.7, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:L/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.LOW, cvssV3_1.getModifiedIntegrityImpact());

        cvssV3_1.modifiedIntegrityImpact(CvssV3_1.ModifiedCIA.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(4.6, score.getEnvironmentalScore(), 0);
        assertEquals(1.8, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:H/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.HIGH, cvssV3_1.getModifiedIntegrityImpact());
    }

    @Test
    public void modifiedAvailabilityImpactTest() {
        cvssV3_1.modifiedAvailabilityImpact(CvssV3_1.ModifiedCIA.NOT_DEFINED);
        Score score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:X", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.NOT_DEFINED, cvssV3_1.getModifiedAvailabilityImpact());

        cvssV3_1.modifiedAvailabilityImpact(CvssV3_1.ModifiedCIA.NONE);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(0, score.getEnvironmentalScore(), 0);
        assertEquals(0, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.NONE, cvssV3_1.getModifiedAvailabilityImpact());

        cvssV3_1.modifiedAvailabilityImpact(CvssV3_1.ModifiedCIA.LOW);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(3.7, score.getEnvironmentalScore(), 0);
        assertEquals(0.7, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:L", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.LOW, cvssV3_1.getModifiedAvailabilityImpact());

        cvssV3_1.modifiedAvailabilityImpact(CvssV3_1.ModifiedCIA.HIGH);
        score = cvssV3_1.calculateScore();
        assertEquals(0, score.getBaseScore(), 0);
        assertEquals(0, score.getImpactSubScore(), 0);
        assertEquals(3.9, score.getExploitabilitySubScore(), 0);
        assertEquals(0, score.getTemporalScore(), 0);
        assertEquals(4.6, score.getEnvironmentalScore(), 0);
        assertEquals(1.8, score.getModifiedImpactSubScore(), 0);
        assertEquals(null, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:H", cvssV3_1.getVector());
        assertEquals(CvssV3_1.ModifiedCIA.HIGH, cvssV3_1.getModifiedAvailabilityImpact());
    }

    @Test
    public void testRegexPattern() {
        // Without temporal vector elements
        String cvss3Vector = "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H";
        Cvss cvssV3 = Cvss.fromVector(cvss3Vector);
        Assert.assertNotNull(cvssV3);
        assertEquals(cvss3Vector, cvssV3.getVector());

        // With temporal vector elements
        cvss3Vector = "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:C";
        cvssV3 = Cvss.fromVector(cvss3Vector);
        Assert.assertNotNull(cvssV3);
        assertEquals(cvss3Vector, cvssV3.getVector());

        // With environmental vector elements
        cvss3Vector = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:C/CR:L/IR:M/AR:L/MAV:P/MAC:H/MPR:N/MUI:R/MS:U/MC:L/MI:L/MA:L";
        cvssV3 = Cvss.fromVector(cvss3Vector);
        Assert.assertNotNull(cvssV3);
        assertEquals(cvss3Vector, cvssV3.getVector());
    }
}
