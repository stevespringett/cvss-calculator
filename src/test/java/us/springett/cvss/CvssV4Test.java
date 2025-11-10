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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CvssV4Test {

    @Test
    public void testBasicScoreCalculation() {
        CvssV4 cvss = new CvssV4()
                .attackVector(CvssV4.AttackVector.NETWORK)
                .attackComplexity(CvssV4.AttackComplexity.LOW)
                .attackRequirements(CvssV4.AttackRequirements.NONE)
                .privilegesRequired(CvssV4.PrivilegesRequired.NONE)
                .userInteraction(CvssV4.UserInteraction.NONE)
                .confidentialityImpact(CvssV4.Impact.HIGH)
                .integrityImpact(CvssV4.Impact.HIGH)
                .availabilityImpact(CvssV4.Impact.HIGH)
                .subsequentConfidentiality(CvssV4.Impact.NONE)
                .subsequentIntegrity(CvssV4.Impact.NONE)
                .subsequentAvailability(CvssV4.Impact.NONE);

        Score score = cvss.calculateScore();
        assertNotNull(score);

        // MacroVector: 000221
        // EQ1=0: AV=N AND PR=N AND UI=N = true
        // EQ2=0: AC=L AND AT=N = true
        // EQ3=0: VC=H AND VI=H = true (VA=H also)
        // EQ4=2: Not safety, SC=N, SI=N, SA=N (no subsequent impact)
        // EQ5=2: E not defined (defaults to X/Unreported)
        // EQ6=1: CR/IR/AR default to HIGH, but (CR=H AND VC=H) OR (IR=H AND VI=H) OR (AR=H AND VA=H) = true -> should be 0
        // Actually EQ6=0 because all three conditions are met
        // MacroVector: 000220 -> lookup gives 9.3
        // With proper severity distance calculation using max_composed data
        assertEquals(9.3, score.getBaseScore(), 0.1);
    }

    @Test
    public void testVectorGeneration() {
        CvssV4 cvss = new CvssV4()
                .attackVector(CvssV4.AttackVector.NETWORK)
                .attackComplexity(CvssV4.AttackComplexity.LOW)
                .attackRequirements(CvssV4.AttackRequirements.NONE)
                .privilegesRequired(CvssV4.PrivilegesRequired.HIGH)
                .userInteraction(CvssV4.UserInteraction.NONE)
                .confidentialityImpact(CvssV4.Impact.HIGH)
                .integrityImpact(CvssV4.Impact.HIGH)
                .availabilityImpact(CvssV4.Impact.HIGH)
                .subsequentConfidentiality(CvssV4.Impact.NONE)
                .subsequentIntegrity(CvssV4.Impact.NONE)
                .subsequentAvailability(CvssV4.Impact.NONE);

        String vector = cvss.getVector();
        assertEquals("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", vector);
    }

    @Test
    public void testVectorParsing() {
        String vectorString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
        Cvss cvss = Cvss.fromVector(vectorString);

        assertNotNull(cvss);
        assertEquals("CVSS:4.0", cvss.getName());

        Score score = cvss.calculateScore();
        assertNotNull(score);
        // Should match the generated vector test
        assertEquals(vectorString, cvss.getVector());
    }

    @Test
    public void testVectorRoundTrip() {
        CvssV4 original = new CvssV4()
                .attackVector(CvssV4.AttackVector.ADJACENT)
                .attackComplexity(CvssV4.AttackComplexity.HIGH)
                .attackRequirements(CvssV4.AttackRequirements.PRESENT)
                .privilegesRequired(CvssV4.PrivilegesRequired.LOW)
                .userInteraction(CvssV4.UserInteraction.PASSIVE)
                .confidentialityImpact(CvssV4.Impact.LOW)
                .integrityImpact(CvssV4.Impact.LOW)
                .availabilityImpact(CvssV4.Impact.NONE)
                .subsequentConfidentiality(CvssV4.Impact.NONE)
                .subsequentIntegrity(CvssV4.Impact.NONE)
                .subsequentAvailability(CvssV4.Impact.NONE);

        String vector = original.getVector();
        Cvss parsed = Cvss.fromVector(vector);

        assertEquals(vector, parsed.getVector());
        assertEquals(original.calculateScore().getBaseScore(),
                parsed.calculateScore().getBaseScore(), 0.01);
    }

    @Test
    public void testWithThreatMetrics() {
        CvssV4 cvss = new CvssV4()
                .attackVector(CvssV4.AttackVector.NETWORK)
                .attackComplexity(CvssV4.AttackComplexity.LOW)
                .attackRequirements(CvssV4.AttackRequirements.NONE)
                .privilegesRequired(CvssV4.PrivilegesRequired.NONE)
                .userInteraction(CvssV4.UserInteraction.NONE)
                .confidentialityImpact(CvssV4.Impact.HIGH)
                .integrityImpact(CvssV4.Impact.HIGH)
                .availabilityImpact(CvssV4.Impact.HIGH)
                .subsequentConfidentiality(CvssV4.Impact.NONE)
                .subsequentIntegrity(CvssV4.Impact.NONE)
                .subsequentAvailability(CvssV4.Impact.NONE)
                .exploitMaturity(CvssV4.ExploitMaturity.ATTACKED);

        String vector = cvss.getVector();
        Assert.assertTrue(vector.contains("/E:A"));

        Score score = cvss.calculateScore();
        assertNotNull(score);
        // Exploit maturity affects the MacroVector (EQ5)
        Assert.assertTrue(score.getBaseScore() >= 0.0 && score.getBaseScore() <= 10.0);
    }

    @Test
    public void testWithSupplementalMetrics() {
        CvssV4 cvss = new CvssV4()
                .attackVector(CvssV4.AttackVector.NETWORK)
                .attackComplexity(CvssV4.AttackComplexity.LOW)
                .attackRequirements(CvssV4.AttackRequirements.NONE)
                .privilegesRequired(CvssV4.PrivilegesRequired.NONE)
                .userInteraction(CvssV4.UserInteraction.NONE)
                .confidentialityImpact(CvssV4.Impact.HIGH)
                .integrityImpact(CvssV4.Impact.HIGH)
                .availabilityImpact(CvssV4.Impact.HIGH)
                .subsequentConfidentiality(CvssV4.Impact.NONE)
                .subsequentIntegrity(CvssV4.Impact.NONE)
                .subsequentAvailability(CvssV4.Impact.NONE)
                .safety(CvssV4.Safety.PRESENT)
                .automatable(CvssV4.Automatable.YES)
                .providerUrgency(CvssV4.ProviderUrgency.RED);

        String vector = cvss.getVector();
        Assert.assertTrue(vector.contains("/S:P"));
        Assert.assertTrue(vector.contains("/AU:Y"));
        Assert.assertTrue(vector.contains("/U:Red"));

        // Supplemental metrics don't affect score
        Score score = cvss.calculateScore();
        assertNotNull(score);
    }

    @Test(expected = MalformedVectorException.class)
    public void testMissingMandatoryMetrics() {
        String vectorString = "CVSS:4.0/AV:N/AC:L";
        Cvss.fromVector(vectorString);
    }

    @Test(expected = MalformedVectorException.class)
    public void testInvalidPrefix() {
        String vectorString = "CVSS:3.1/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
        Cvss.fromVector(vectorString);
    }

    @Test(expected = MalformedVectorException.class)
    public void testDuplicateMetrics() {
        String vectorString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AV:A";
        Cvss.fromVector(vectorString);
    }

    @Test
    public void testOfficialTestVectors() {
        // Test cases from official CVSS v4.0 test suite
        TestCase[] testCases = new TestCase[]{
                // randomly generated test cases
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "None"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/CR:M/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/CR:M/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 7.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:U/CR:M/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:U/CR:M/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 5.5, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:M/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:M/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 6.6, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:M/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 7.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:L/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 7.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:H/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 7.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 8.6, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:H/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:H/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 8.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:L/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 7.4, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVI:L/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVI:L/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 5.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 6.6, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:P/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:P/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 6.5, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 6.6, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:H/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 8.4, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 9.1, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/AU:Y/R:I/V:C/RE:L/U:Amber", 7.5, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:C/RE:L/U:Clear
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:C/RE:L/U:Clear", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:C/RE:L/U:Clear
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:C/RE:L/U:Clear", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:C/RE:L/U:Clear
                new TestCase("CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:L/AR:L/MAV:L/MAC:L/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:A/V:C/RE:L/U:Clear", 8.6, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M/AR:L", 8.9, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:H/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:H/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:L/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N"
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:L/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:H/MSC:N/MSI:N/MSA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:L/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:L/MSC:N/MSI:N/MSA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:N/MSA:N", 5.1, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N", 0.0, "None"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:A/MVC:N/MVI:N/MVA:L/MSC:N/MSI:N/MSA:N", 5.1, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:A/MVC:N/MVI:H/MVA:N/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:A/MVC:N/MVI:H/MVA:N/MSC:N/MSI:N/MSA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:P/MVC:N/MVI:H/MVA:N/MSC:N/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MUI:P/MVC:N/MVI:H/MVA:N/MSC:N/MSI:N/MSA:N", 7.1, "High"),

                // strategically generated cases
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "None"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "None"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 5.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", 7.9, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.2, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.4, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.1, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 5.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 5.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 5.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "None"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:H", 10.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:L", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:H", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:L", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:H", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:L", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:H", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:L", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:H/SA:N", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:H", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:H", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:H/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:H/SA:H", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:H/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:H/SA:L", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:H/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:H/SA:N", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:L/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:L/SA:H", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:L/SA:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:L/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:L/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:H", 9.9, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:H/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:H/SI:L/SA:L", 8.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:L/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:L/SI:L/SA:L", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:N/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:N/SI:L/SA:L", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:H/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:H/SI:L/SA:L", 6.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 5.3, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:L/SA:L", 5.3, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:H/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:H/SI:L/SA:L", 6.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L", 5.3, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:L/SA:L", 5.3, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N", 4.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 1.0, "Low"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:A
                new TestCase("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:A", 4.4, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:A
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:A", 1.0, "Low"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 8.9, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P
                new TestCase("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P", 1.6, "Low"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P", 0.3, "Low"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:U
                new TestCase("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:U", 0.7, "Low"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U", 0.1, "Low"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:H/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:H/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:H/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:H/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:H/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:H/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:M/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:M/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:M/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:M/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:M/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:M/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:L/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:L/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:L/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:L/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:L/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/IR:L/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:M/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:L/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:L/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:L/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:L/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:H/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:H/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:H/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:H/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:H/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:H/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M/AR:M", 9.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M/AR:L", 9.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:L/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:L/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:L/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:L/AR:M", 9.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:L/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:L/AR:L", 8.9, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H/AR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:H/AR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M/AR:M", 9.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:M/AR:L", 8.9, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:M", 8.9, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L", 8.9, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:N
                new TestCase("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:N", 8.6, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:A
                new TestCase("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:A", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:L
                new TestCase("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:L", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:P
                new TestCase("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/MAV:P", 6.9, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVI:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVI:H", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVI:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVI:L", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVI:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVI:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:H", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:H/MVI:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:H/MVI:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:H/MVI:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:H/MVI:L", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:H/MVI:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:H/MVI:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:L", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:L/MVI:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:L/MVI:H", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:L/MVI:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:L/MVI:L", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:L/MVI:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:L/MVI:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:H", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:L", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSA:S
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSA:S", 9.8, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSA:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSA:L", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S", 9.8, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S/MSA:S
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S/MSA:S", 9.8, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S/MSA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S/MSA:H", 9.8, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S/MSA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S/MSA:L", 9.8, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:S/MSA:N", 9.7, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H/MSA:S
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H/MSA:S", 9.8, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H/MSA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H/MSA:H", 9.4, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H/MSA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H/MSA:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:H/MSA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L/MSA:S
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L/MSA:S", 9.8, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L/MSA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L/MSA:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L/MSA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L/MSA:L", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:L/MSA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N/MSA:S
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N/MSA:S", 9.7, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N/MSA:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N/MSA:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N/MSA:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N/MSA:L", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N/MSA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/MSI:N/MSA:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/MVC:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/MVC:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/MVC:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/MVC:L", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/MVC:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/MVC:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/MVC:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/MVC:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/MVC:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/MVC:L", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/MVC:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/MVC:N", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/MVC:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/MVC:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/MVC:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/MVC:L", 8.8, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/MVC:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/MVC:N", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/AU:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/AU:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/AU:Y
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/AU:Y", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N/R:A
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N/R:A", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N/R:U
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N/R:U", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N/R:I
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N/R:I", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N/V:D
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N/V:D", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N/V:C
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N/V:C", 7.2, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/RE:L
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/RE:L", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/RE:M
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/RE:M", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/RE:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/RE:H", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Clear
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Clear", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Green
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Green", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Amber
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Amber", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Red
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Red", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:I/V:C/RE:H/U:Red
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:I/V:C/RE:H/U:Red", 9.3, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/AU:Y
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/AU:Y", 10.0, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P
                new TestCase("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 7.1, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/CR:H/MVC:H
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/CR:H/MVC:H", 8.7, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/MSA:S/S:P
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/MSA:S/S:P", 9.7, "Critical"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/AU:Y
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/AU:Y", 8.5, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:H/SI:H/SA:H/V:C
                new TestCase("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:H/SI:H/SA:H/V:C", 5.8, "Medium"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:M/AR:L/MAV:A/MVC:H/MVI:L/S:P/AU:Y/R:U/V:C/RE:M/U:Amber
                new TestCase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:M/AR:L/MAV:A/MVC:H/MVI:L/S:P/AU:Y/R:U/V:C/RE:M/U:Amber", 7.1, "High"),
                // https://www.first.org/cvss/calculator/4-0#CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:M/IR:H/AR:M/MAC:L/MPR:N/MSI:S/S:P/R:A
                new TestCase("CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:M/IR:H/AR:M/MAC:L/MPR:N/MSI:S/S:P/R:A", 6.9, "Medium")
        };

        int passed = 0;
        int failed = 0;
        StringBuilder failures = new StringBuilder();

        for (int i = 0; i < testCases.length; i++) {
            TestCase tc = testCases[i];
            try {
                Cvss cvss = Cvss.fromVector(tc.vector);
                Score score = cvss.calculateScore();
                double actualScore = score.getBaseScore();

                // Allow 0.1 tolerance for floating point comparison
                if (Math.abs(actualScore - tc.expectedScore) <= 0.1) {
                    passed++;
                } else {
                    failed++;
                    failures.append(String.format("\nTest case %d FAILED:\n  Vector: %s\n  Expected: %.1f (%s)\n  Actual: %.1f\n",
                            i + 1, tc.vector, tc.expectedScore, tc.severity, actualScore));
                }
            } catch (Exception e) {
                failed++;
                failures.append(String.format("\nTest case %d ERROR:\n  Vector: %s\n  Expected: %.1f (%s)\n  Error: %s\n",
                        i + 1, tc.vector, tc.expectedScore, tc.severity, e.getMessage()));
            }
        }

        String summary = String.format("\nOfficial Test Vectors: %d passed, %d failed out of %d total",
                passed, failed, testCases.length);

        if (failed > 0) {
            Assert.fail(summary + failures);
        }
    }

    private static class TestCase {
        final String vector;
        final double expectedScore;
        final String severity;

        TestCase(String vector, double expectedScore, String severity) {
            this.vector = vector;
            this.expectedScore = expectedScore;
            this.severity = severity;
        }
    }
}
