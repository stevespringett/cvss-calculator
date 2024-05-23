package us.springett.cvss;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CvssV3_1NotDefinedRegression {
    /**
     * Regression for CVSS Vector CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:H/MUI:X/MS:U/MC:H/MI:H/MA:H
     * Correct environmental score is 6.4 according to https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAV:A/MAC:H/MPR:H/MS:U/MC:H/MI:H/MA:H
     * Problem: If MUI is NOT_DEFINED the modifiedExploitabilitySubScore is calculated wrongly (multiplication with 0 instead of using the UI-value)
     */
    @Test
    public void regressionForEnvironmentalScore1() {
        Cvss vector = Cvss.fromVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:H/MUI:X/MS:U/MC:H/MI:H/MA:H");

        double environmentalScore = vector.calculateScore().getEnvironmentalScore();

        assertEquals("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAV:A/MAC:H/MPR:H/MS:U/MC:H/MI:H/MA:H", vector.getVector());
        assertEquals(6.4, environmentalScore, 0.01);
    }

    /**
     * Regression for CVSS Vector CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:X/MUI:N/MS:U/MC:H/MI:H/MA:H
     * Correct environmental score is 7.5 according to https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:X/MUI:N/MS:U/MC:H/MI:H/MA:H
     * Problem: If MPR is NOT_DEFINED the modifiedExploitabilitySubScore is calculated wrongly (multiplication with 0 instead of using the PR-value)
     */
    @Test
    public void regressionForEnvironmentalScore2() {
        Cvss vector = Cvss.fromVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:X/MUI:N/MS:U/MC:H/MI:H/MA:H");

        double environmentalScore = vector.calculateScore().getEnvironmentalScore();

        assertEquals("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAV:A/MAC:H/MUI:N/MS:U/MC:H/MI:H/MA:H", vector.getVector());
        assertEquals(7.5, environmentalScore, 0.01);
    }

    /**
     * Regression for CVSS Vector CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:X/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H
     * Correct environmental score is 7.5 according to https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:X/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H
     * Problem: If MAC is NOT_DEFINED the modifiedExploitabilitySubScore is calculated wrongly (multiplication with 0 instead of using the AC-value)
     */
    @Test
    public void regressionForEnvironmentalScore3() {
        Cvss vector = Cvss.fromVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:X/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H");

        double environmentalScore = vector.calculateScore().getEnvironmentalScore();

        assertEquals("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAV:A/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H", vector.getVector());
        assertEquals(7.5, environmentalScore, 0.01);
    }

    /**
     * Regression for CVSS Vector CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:X/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H
     * Correct environmental score is 8.1 according to https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:X/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H
     * Problem: If MAC is NOT_DEFINED the modifiedExploitabilitySubScore is calculated wrongly (multiplication with 0 instead of using the AC-value)
     */
    @Test
    public void regressionForEnvironmentalScore4() {
        Cvss vector = Cvss.fromVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:X/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H");

        double environmentalScore = vector.calculateScore().getEnvironmentalScore();

        assertEquals("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H", vector.getVector());
        assertEquals(8.1, environmentalScore, 0.01);
    }

    /**
     * Regression for CVSS Vector CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:X/MC:H/MI:H/MA:H
     * Correct environmental score is 7.5 according to https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:X/MC:H/MI:H/MA:H
     * Problem: If MS is NOT_DEFINED the modifiedExploitabilitySubScore is calculated wrongly
     */
    @Test
    public void regressionForEnvironmentalScore5() {
        String vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:X/MC:H/MI:H/MA:H";
        Cvss vector = Cvss.fromVector(vectorString);

        double environmentalScore = vector.calculateScore().getEnvironmentalScore();

        assertEquals("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MC:H/MI:H/MA:H", vector.getVector());
        assertEquals(7.5, environmentalScore, 0.01);
    }

    @Test
    public void regressionForEnvironmentalScore6() {
        String vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:X/MI:H/MA:H";
        Cvss vector = Cvss.fromVector(vectorString);

        double environmentalScore = vector.calculateScore().getEnvironmentalScore();

        assertEquals("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MI:H/MA:H", vector.getVector());
        assertEquals(7.5, environmentalScore, 0.01);
    }

    @Test
    public void regressionForEnvironmentalScore7() {
        String vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:X/MA:H";
        Cvss vector = Cvss.fromVector(vectorString);

        double environmentalScore = vector.calculateScore().getEnvironmentalScore();

        assertEquals("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MA:H", vector.getVector());
        assertEquals(7.5, environmentalScore, 0.01);
    }

    @Test
    public void regressionForEnvironmentalScore8() {
        String vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:X/CR:X/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:X";
        Cvss vector = Cvss.fromVector(vectorString);

        double environmentalScore = vector.calculateScore().getEnvironmentalScore();

        assertEquals("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:H", vector.getVector());
        assertEquals(7.5, environmentalScore, 0.01);
    }
}
