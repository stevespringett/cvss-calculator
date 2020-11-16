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

/**
 * Defines a Score object that defines base, impact, and exploitability scores.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class Score {

    private final double baseScore;
    private final double impactSubScore;
    private final double exploitabilitySubScore;
    private final double temporalScore;
    private final double environmentalScore;
    private final double modifiedImpactSubScore;

    public Score(double baseScore, double impactSubScore, double exploitabilitySubScore) {
        this(baseScore, impactSubScore, exploitabilitySubScore, -1);
    }

    public Score(double baseScore, double impactSubScore, double exploitabilitySubScore, double temporalScore) {
        this(baseScore, impactSubScore, exploitabilitySubScore, temporalScore, -1, -1);
    }

    public Score(double baseScore, double impactSubScore, double exploitabilitySubScore, double temporalScore, double environmentalScore, double modifiedImpactSubScore) {
        this.baseScore = baseScore;
        this.impactSubScore = impactSubScore;
        this.exploitabilitySubScore = exploitabilitySubScore;
        this.temporalScore = temporalScore;
        this.environmentalScore = environmentalScore;
        this.modifiedImpactSubScore = modifiedImpactSubScore;
    }

    /**
     * Returns the base score.
     * @return the base score
     */
    public double getBaseScore() {
        return baseScore;
    }

    /**
     * Returns the impact subscore.
     * @return the impact subscore
     */
    public double getImpactSubScore() {
        return impactSubScore;
    }

    /**
     * Returns the exploitability subscore.
     * @return the exploitability subscore
     */
    public double getExploitabilitySubScore() {
        return exploitabilitySubScore;
    }

    /**
     * Returns the temporal subscore.
     * @return the temporal subscore
     */
    public double getTemporalScore() {
        return temporalScore;
    }

    /**
     * Returns the environmental score.
     * @return the environmental score
     */
    public double getEnvironmentalScore() {
        return environmentalScore;
    }

    /**
     * Returns the modified impact subscore.
     * @return the modified impact subscore
     */
    public double getModifiedImpactSubScore() {
        return modifiedImpactSubScore;
    }
}