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
 * Calculates CVSSv3 scores and vector.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class CvssV3 implements Cvss {

    private static final double exploitabilityCoefficient = 8.22;
    private static final double scopeCoefficient = 1.08;

    private AttackVector av;
    private AttackComplexity ac;
    private PrivilegesRequired pr;
    private UserInteraction ui;
    private Scope s;
    private CIA c;
    private CIA i;
    private CIA a;

    public CvssV3 attackVector(AttackVector av) {
        this.av = av;
        return this;
    }

    public CvssV3 attackComplexity(AttackComplexity ac) {
        this.ac = ac;
        return this;
    }

    public CvssV3 privilegesRequired(PrivilegesRequired pr) {
        this.pr = pr;
        return this;
    }

    public CvssV3 userInteraction(UserInteraction ui) {
        this.ui = ui;
        return this;
    }

    public CvssV3 scope(Scope s) {
        this.s = s;
        return this;
    }

    public CvssV3 confidentiality(CIA c) {
        this.c = c;
        return this;
    }

    public CvssV3 integrity(CIA i) {
        this.i = i;
        return this;
    }

    public CvssV3 availability(CIA a) {
        this.a = a;
        return this;
    }

    public enum AttackVector {
        NETWORK(0.85, "N"),
        ADJACENT(0.62, "A"),
        LOCAL(0.55, "L"),
        PHYSICAL(0.2, "P");

        private final double weight;
        private final String shorthand;
        AttackVector(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
    }

    public enum AttackComplexity {
        LOW(0.77, "L"),
        HIGH(0.44, "H");

        private final double weight;
        private final String shorthand;
        AttackComplexity(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
    }

    public enum PrivilegesRequired  {
        NONE(0.85, 0.85, "N"),
        LOW(0.62, 0.68, "L"),
        HIGH(0.27, 0.5, "H");

        private final double weight;
        private final double scopeChangedWeight;
        private final String shorthand;
        PrivilegesRequired(double weight, double scopeChangedWeight, String shorthand) {
            this.weight = weight;
            this.scopeChangedWeight = scopeChangedWeight;
            this.shorthand = shorthand;
        }
    }

    public enum UserInteraction {
        NONE(0.85, "N"),
        REQUIRED(0.62, "R");

        private final double weight;
        private final String shorthand;
        UserInteraction(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
    }

    public enum Scope {
        UNCHANGED(6.42, "U"),
        CHANGED(7.52, "C");

        private final double weight;
        private final String shorthand;
        Scope(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
    }

    public enum CIA {
        NONE(0, "N"),
        LOW(0.22, "L"),
        HIGH(0.56, "H");

        private final double weight;
        private final String shorthand;
        CIA(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
    }

    /**
     * {@inheritDoc}
     */
    public Score calculateScore() {
        final double prWeight = (Scope.UNCHANGED == s) ? pr.weight : pr.scopeChangedWeight;
        final double baseScore;
        final double impactSubScore;
        final double exploitabalitySubScore = exploitabilityCoefficient * av.weight * ac.weight * prWeight * ui.weight;
        final double impactSubScoreMultiplier = (1 - ((1 - c.weight) * (1 - i.weight) * (1 - a.weight)));

        if (Scope.UNCHANGED == s) {
            impactSubScore = s.weight * impactSubScoreMultiplier;
        } else {
            impactSubScore = s.weight * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15);
        }

        if (impactSubScore <= 0) {
            baseScore = 0;
        } else {
            if (Scope.UNCHANGED == s) {
                baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10));
            } else {
                baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * scopeCoefficient, 10));
            }
        }
        return new Score(baseScore, roundNearestTenth(impactSubScore), roundNearestTenth(exploitabalitySubScore));
    }

    private double roundUp1(double d) {
        return Math.ceil(d * 10) / 10;
    }

    private double roundNearestTenth(double d) {
        return Math.round(d * 10.0) / 10.0;
    }

    /**
     * {@inheritDoc}
     */
    public String getVector() {
        return "CVSS:3.0/" +
                "AV:" + av.shorthand + "/" +
                "AC:" + ac.shorthand + "/" +
                "PR:" + pr.shorthand + "/" +
                "UI:" + ui.shorthand + "/" +
                "S:" + s.shorthand + "/" +
                "C:" + c.shorthand + "/" +
                "I:" + i.shorthand + "/" +
                "A:" + a.shorthand;
    }
}
