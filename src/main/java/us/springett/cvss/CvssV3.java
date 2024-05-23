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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static us.springett.cvss.Parser.requireNonNull;

/**
 * Calculates CVSSv3 scores and vector.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class CvssV3 implements Cvss {

    static final String VECTOR_PREFIX = "CVSS:3.0";

    protected static final double NO_VALUE = -1.0;
    protected static final double exploitabilityCoefficient = 8.22;
    protected static final double scopeCoefficient = 1.08;

    protected AttackVector av;
    protected AttackComplexity ac;
    protected PrivilegesRequired pr;
    protected UserInteraction ui;
    protected Scope s;
    protected Exploitability e;
    protected RemediationLevel rl;
    protected ReportConfidence rc;
    protected CIA c;
    protected CIA i;
    protected CIA a;

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

    static final class Parser implements us.springett.cvss.Parser<CvssV3> {

        private static final List<String> MANDATORY_METRICS = Arrays.asList(
                "AV", "AC", "PR", "UI", "S", "C", "I", "A" // Base metrics.
        );

        @Override
        public CvssV3 parseVector(final String vector) {
            if (vector == null || vector.isEmpty()) {
                throw new MalformedVectorException("Vector must not be null or empty");
            }

            final String[] segments = vector.split("/");
            if (segments.length < (1 + MANDATORY_METRICS.size())) {
                throw new MalformedVectorException(String.format(
                        "Vector must consist of at least %d segments (%s prefix and mandatory metrics %s), but has only %s",
                        (1 + MANDATORY_METRICS.size()), VECTOR_PREFIX, String.join(", ", MANDATORY_METRICS), segments.length
                ));
            }
            if (!VECTOR_PREFIX.equals(segments[0])) {
                throw new MalformedVectorException("Missing \"CVSS:3.0\" prefix");
            }

            final CvssV3 cvss = new CvssV3();
            final Set<String> metricsSeen = new HashSet<>();
            for (int i = 1; i < segments.length; i++) {
                final String[] metricParts = segments[i].split(":", 2);
                if (metricParts.length < 2) {
                    throw new MalformedVectorException(String.format(
                            "Segment #%d is malformed; Expected format <METRIC>:<VALUE>, but got \"%s\"",
                            (i + 1), segments[i]
                    ));
                }

                final String metric = metricParts[0];
                final char metricValue = metricParts[1].charAt(0);

                switch (metric) {
                    // Base.
                    case "AV":
                        cvss.attackVector(requireNonNull(metric, metricValue, AttackVector::fromChar));
                        break;
                    case "AC":
                        cvss.attackComplexity(requireNonNull(metric, metricValue, AttackComplexity::fromChar));
                        break;
                    case "PR":
                        cvss.privilegesRequired(requireNonNull(metric, metricValue, PrivilegesRequired::fromChar));
                        break;
                    case "UI":
                        cvss.userInteraction(requireNonNull(metric, metricValue, UserInteraction::fromChar));
                        break;
                    case "S":
                        cvss.scope(requireNonNull(metric, metricValue, Scope::fromChar));
                        break;
                    case "C":
                        cvss.confidentiality(requireNonNull(metric, metricValue, CIA::fromString));
                        break;
                    case "I":
                        cvss.integrity(requireNonNull(metric, metricValue, CIA::fromString));
                        break;
                    case "A":
                        cvss.availability(requireNonNull(metric, metricValue, CIA::fromString));
                        break;
                    // Temporal.
                    case "E":
                        cvss.exploitability(requireNonNull(metric, metricValue, Exploitability::fromChar));
                        break;
                    case "RL":
                        cvss.remediationLevel(requireNonNull(metric, metricValue, RemediationLevel::fromChar));
                        break;
                    case "RC":
                        cvss.reportConfidence(requireNonNull(metric, metricValue, ReportConfidence::fromChar));
                        break;
                    // Environmental.
                    case "CR":
                    case "IR":
                    case "AR":
                    case "MAV":
                    case "MAC":
                    case "MPR":
                    case "MUI":
                    case "MS":
                    case "MC":
                    case "MI":
                    case "MA":
                        // TODO: Handle these (https://github.com/stevespringett/cvss-calculator/issues/66).
                        break;
                    default:
                        throw new MalformedVectorException("Unknown metric: " + metric);
                }

                metricsSeen.add(metric);
            }

            final List<String> missingMetrics = MANDATORY_METRICS.stream()
                    .filter(metric -> !metricsSeen.contains(metric))
                    .collect(Collectors.toList());
            if (!missingMetrics.isEmpty()) {
                throw new MalformedVectorException("Missing mandatory metrics: " + String.join(", ", missingMetrics));
            }

            return cvss;
        }

    }

    public enum AttackVector {
        NETWORK(0.85, 'N'),
        ADJACENT(0.62, 'A'),
        LOCAL(0.55, 'L'),
        PHYSICAL(0.2, 'P');

        protected final double weight;
        protected final char shorthand;
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
        LOW(0.77, 'L'),
        HIGH(0.44, 'H');

        protected final double weight;
        protected final char shorthand;
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

    public enum PrivilegesRequired  {
        NONE(0.85, 0.85, 'N'),
        LOW(0.62, 0.68, 'L'),
        HIGH(0.27, 0.5, 'H');

        protected final double weight;
        protected final double scopeChangedWeight;
        protected final char shorthand;
        PrivilegesRequired(double weight, double scopeChangedWeight, char shorthand) {
            this.weight = weight;
            this.scopeChangedWeight = scopeChangedWeight;
            this.shorthand = shorthand;
        }
        public static PrivilegesRequired fromChar(char c) {
            for (PrivilegesRequired e : PrivilegesRequired.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum UserInteraction {
        NONE(0.85, 'N'),
        REQUIRED(0.62, 'R');

        protected final double weight;
        protected final char shorthand;
        UserInteraction(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static UserInteraction fromChar(char c) {
            for (UserInteraction e : UserInteraction.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum Scope {
        UNCHANGED(6.42, 'U'),
        CHANGED(7.52, 'C');

        protected final double weight;
        protected final char shorthand;
        Scope(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static Scope fromChar(char c) {
            for (Scope e : Scope.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    // Temporal
    public enum Exploitability {
        UNPROVEN(0.91, 'U'),
        POC(0.94, 'P'),
        FUNCTIONAL(0.97, 'F'),
        HIGH(1.0, 'H'),
        NOT_DEFINED(1.0, 'X'),;

        protected final double weight;
        protected final char shorthand;
        Exploitability(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static Exploitability fromChar(char c) {
            for (Exploitability e : Exploitability.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum RemediationLevel  {
        UNAVAILABLE(1.0, 'U'),
        WORKAROUND(0.97, 'W'),
        TEMPORARY(0.96, 'T'),
        OFFICIAL(0.95, 'O'),
        NOT_DEFINED(1.0, 'X'),;

        protected final double weight;
        protected final char shorthand;
        RemediationLevel (double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static RemediationLevel fromChar(char c) {
            for (RemediationLevel e : RemediationLevel.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ReportConfidence  {
        UNKNOWN(0.92, 'U'),
        REASONABLE(0.96, 'R'),
        CONFIRMED(1.0, 'C'),
        NOT_DEFINED(1.0, 'X'),;

        protected final double weight;
        protected final char shorthand;
        ReportConfidence (double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static ReportConfidence fromChar(char c) {
            for (ReportConfidence e : ReportConfidence.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }
    // End-Temporal

    public enum CIA {
        NONE(0, 'N'),
        LOW(0.22, 'L'),
        HIGH(0.56, 'H');

        protected final double weight;
        protected final char shorthand;
        CIA(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
        public static CIA fromString(char c) {
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

    protected double roundNearestTenth(double d) {
        if (d < 0) {
            return 0;
        }

        return Math.round(d * 10.0) / 10.0;
    }

    /**
     * {@inheritDoc}
     */
    public String getVector() {
        final List<String> vectorParts = new ArrayList<>(Arrays.asList(
                VECTOR_PREFIX,
                "AV:" + av.shorthand,
                "AC:" + ac.shorthand,
                "PR:" + pr.shorthand,
                "UI:" + ui.shorthand,
                "S:" + s.shorthand,
                "C:" + c.shorthand,
                "I:" + i.shorthand,
                "A:" + a.shorthand
        ));

        if (e != null) {
            vectorParts.add("E:" + e.shorthand);
        }
        if (rl != null) {
            vectorParts.add("RL:" + rl.shorthand);
        }
        if (rc != null) {
            vectorParts.add("RC:" + rc.shorthand);
        }

        return String.join("/", vectorParts);
    }

    public AttackVector getAttackVector() {
        return av;
    }

    public AttackComplexity getAttackComplexity() {
        return ac;
    }

    public PrivilegesRequired getPrivilegesRequired() {
        return pr;
    }

    public UserInteraction getUserInteraction() {
        return ui;
    }

    public Scope getScope() {
        return s;
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
