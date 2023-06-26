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
 * Calculates CVSSv2 scores and vector.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class CvssV2 implements Cvss {

    private static final double NO_VALUE = -1.0;
    private AttackVector av;
    private AttackComplexity ac;
    private Authentication au;
    private Exploitability e;
    private RemediationLevel rl;
    private ReportConfidence rc;
    private CIA c;
    private CIA i;
    private CIA a;

    public CvssV2 attackVector(AttackVector av) {
        this.av = av;
        return this;
    }

    public CvssV2 attackComplexity(AttackComplexity ac) {
        this.ac = ac;
        return this;
    }

    public CvssV2 authentication(Authentication au) {
        this.au = au;
        return this;
    }

    public CvssV2 confidentiality(CIA c) {
        this.c = c;
        return this;
    }

    public CvssV2 integrity(CIA i) {
        this.i = i;
        return this;
    }

    public CvssV2 availability(CIA a) {
        this.a = a;
        return this;
    }

    public CvssV2 exploitability(Exploitability e) {
        this.e = e;
        return this;
    }

    public CvssV2 remediationLevel(RemediationLevel rl) {
        this.rl = rl;
        return this;
    }

    public CvssV2 reportConfidence(ReportConfidence rc) {
        this.rc = rc;
        return this;
    }

    public enum AttackVector {
        NETWORK(1.0, 'N'),
        ADJACENT(0.646, 'A'),
        LOCAL(0.395, 'L');

        private final double weight;
        private final char shorthand;
        AttackVector(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static AttackVector fromChar(char c) {
            for (AttackVector e : AttackVector.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum AttackComplexity {
        LOW(0.71, 'L'),
        MEDIUM(0.61, 'M'),
        HIGH(0.35, 'H');

        private final double weight;
        private final char shorthand;
        AttackComplexity(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static AttackComplexity fromChar(char c) {
            for (AttackComplexity e : AttackComplexity.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum Authentication  {
        NONE(0.704, 'N'),
        SINGLE(0.56, 'S'),
        MULTIPLE(0.45, 'M');

        private final double weight;
        private final char shorthand;
        Authentication(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static Authentication fromChar(char c) {
            for (Authentication e : Authentication.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    // Temporal
    public enum Exploitability {
        UNPROVEN(0.85, "U"),
        POC(0.9, "POC"),
        FUNCTIONAL(0.95, "F"),
        HIGH(1.0, "H"),
        NOT_DEFINED(1.0, "ND"),;

        private final double weight;
        private final String shorthand;
        Exploitability(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static Exploitability fromString(String text) {
            for (Exploitability e : Exploitability.values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum RemediationLevel  {
        UNAVAILABLE(1.0, "U"),
        WORKAROUND(0.95, "W"),
        TEMPORARY(0.90, "TF"),
        OFFICIAL(0.87, "OF"),
        NOT_DEFINED(1.0, "ND"),;

        private final double weight;
        private final String shorthand;
        RemediationLevel (double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static RemediationLevel  fromString(String text) {
            for (RemediationLevel  e : RemediationLevel .values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ReportConfidence  {
        UNCONFIRMED(0.90, "UC"),
        UNCORROBORATED(0.95, "UR"),
        CONFIRMED(1.0, "C"),
        NOT_DEFINED(1.0, "ND"),;

        private final double weight;
        private final String shorthand;
        ReportConfidence (double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static ReportConfidence  fromString(String text) {
            for (ReportConfidence  e : ReportConfidence .values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }
    // End-Temporal

    public enum CIA {
        NONE(0.0, 'N'),
        PARTIAL(0.275, 'P'),
        COMPLETE(0.660, 'C');

        private final double weight;
        private final char shorthand;
        CIA(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static CIA fromChar(char c) {
            for (CIA e : CIA.values()) {
                if (e.shorthand==c) {
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
        final double baseScore;
        final double impactSubScore;
        final double exploitabalitySubScore;
        final double temporalScore;

        impactSubScore = 10.41 * (1 - (1 - c.weight) * (1 - i.weight) * (1 - a.weight));
        exploitabalitySubScore = 20 * av.weight * ac.weight * au.weight;
        baseScore = roundNearestTenth(((0.6 * impactSubScore) + (0.4 * exploitabalitySubScore) - 1.5) * f(impactSubScore));

        if (e != null && e.weight != NO_VALUE &&
                rl != null && rl.weight != NO_VALUE &&
                rc != null && rc.weight != NO_VALUE) {
            temporalScore = roundNearestTenth(baseScore * e.weight * rl.weight * rc.weight);
        } else {
            temporalScore = NO_VALUE;
        }

        return new Score(baseScore, roundNearestTenth(impactSubScore), roundNearestTenth(exploitabalitySubScore), temporalScore);
    }

    private double f(double impact) {
        return (impact == 0) ? 0 : 1.176;
    }

    private double roundNearestTenth(double d) {
        return Math.round(d * 10.0) / 10.0;
    }

    /**
     * {@inheritDoc}
     */
    public String getVector() {
        return "(" +
                "AV:" + av.shorthand + "/" +
                "AC:" + ac.shorthand + "/" +
                "Au:" + au.shorthand + "/" +
                "C:" + c.shorthand + "/" +
                "I:" + i.shorthand + "/" +
                "A:" + a.shorthand +
                ((e != null && rl != null && rc != null) ? (
                        "/E:" + e.shorthand + "/" +
                        "RL:" + rl.shorthand + "/" +
                        "RC:" + rc.shorthand + ")") : ")");
    }

    public AttackVector getAttackVector() {
        return av;
    }

    public AttackComplexity getAttackComplexity() {
        return ac;
    }

    public Authentication getAuthentication() {
        return au;
    }

    public Exploitability getExploitability() {
        return e;
    }

    public RemediationLevel getRemediationLevel() {
        return rl;
    }

    public ReportConfidence getReportConfidence() {
        return rc;
    }

    public CIA getConfidentiality() {
        return c;
    }

    public CIA getIntegrity() {
        return i;
    }

    public CIA getAvailability() {
        return a;
    }

    @Override
    public String toString() {
        return getVector();
    }
}
