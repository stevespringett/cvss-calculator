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

    private static final double NO_VALUE = -1.0;
    private static final double exploitabilityCoefficient = 8.22;
    private static final double scopeCoefficient = 1.08;

    private AttackVector av;
    private AttackComplexity ac;
    private PrivilegesRequired pr;
    private UserInteraction ui;
    private Scope s;
    private Exploitability e;
    private RemediationLevel rl;
    private ReportConfidence rc;
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

    public CvssV3 exploitability(Exploitability e) {
        this.e = e;
        return this;
    }

    public CvssV3 remediationLevel(RemediationLevel rl) {
        this.rl = rl;
        return this;
    }

    public CvssV3 reportConfidence(ReportConfidence rc) {
        this.rc = rc;
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
        public static AttackVector fromString(String text) {
            for (AttackVector e : AttackVector.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
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
        public static AttackComplexity fromString(String text) {
            for (AttackComplexity e : AttackComplexity.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
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
        public static PrivilegesRequired fromString(String text) {
            for (PrivilegesRequired e : PrivilegesRequired.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
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
        public static UserInteraction fromString(String text) {
            for (UserInteraction e : UserInteraction.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
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
        public static Scope fromString(String text) {
            for (Scope e : Scope.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    // Temporal
    public enum Exploitability {
        UNPROVEN(0.91, "U"),
        POC(0.94, "P"),
        FUNCTIONAL(0.97, "F"),
        HIGH(1.0, "H"),
        NOT_DEFINED(1.0, "X"),;

        private final double weight;
        private final String shorthand;
        Exploitability(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static Exploitability fromString(String text) {
            for (Exploitability e : Exploitability.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum RemediationLevel  {
        UNAVAILABLE(1.0, "U"),
        WORKAROUND(0.97, "W"),
        TEMPORARY(0.96, "T"),
        OFFICIAL(0.95, "O"),
        NOT_DEFINED(1.0, "X"),;

        private final double weight;
        private final String shorthand;
        RemediationLevel (double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static RemediationLevel fromString(String text) {
            for (RemediationLevel e : RemediationLevel.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ReportConfidence  {
        UNKNOWN(0.92, "U"),
        REASONABLE(0.96, "R"),
        CONFIRMED(1.0, "C"),
        NOT_DEFINED(1.0, "X"),;

        private final double weight;
        private final String shorthand;
        ReportConfidence (double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static ReportConfidence fromString(String text) {
            for (ReportConfidence e : ReportConfidence.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
        }
    }
    // End-Temporal

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
        public static CIA fromString(String text) {
            for (CIA e : CIA.values()) {
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
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
        final double temporalScore;

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

        if (e != null && e.weight != NO_VALUE &&
                rl != null && rl.weight != NO_VALUE &&
                rc != null && rc.weight != NO_VALUE) {
            temporalScore = roundUp1(baseScore * e.weight * rl.weight * rc.weight);
        } else {
            temporalScore = NO_VALUE;
        }

        return new Score(baseScore, roundNearestTenth(impactSubScore), roundNearestTenth(exploitabalitySubScore), temporalScore);
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
                "A:" + a.shorthand +
                ((e != null && rl != null && rc != null) ? (
                        "/E:" + e.shorthand + "/" +
                                "RL:" + rl.shorthand + "/" +
                                "RC:" + rc.shorthand) : "");
    }

    @Override
    public String toString() {
        return getVector();
    }
}
