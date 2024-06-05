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
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static us.springett.cvss.Parser.requireNonNull;

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
    private Exploitability e = Exploitability.NOT_DEFINED;
    private RemediationLevel rl = RemediationLevel.NOT_DEFINED;
    private ReportConfidence rc = ReportConfidence.NOT_DEFINED;
    private CIA c;
    private CIA i;
    private CIA a;

    public CvssV2 attackVector(AttackVector av) {
        this.av = Objects.requireNonNull(av);
        return this;
    }

    public CvssV2 attackComplexity(AttackComplexity ac) {
        this.ac = Objects.requireNonNull(ac);
        return this;
    }

    public CvssV2 authentication(Authentication au) {
        this.au = Objects.requireNonNull(au);
        return this;
    }

    public CvssV2 confidentiality(CIA c) {
        this.c = Objects.requireNonNull(c);
        return this;
    }

    public CvssV2 integrity(CIA i) {
        this.i = Objects.requireNonNull(i);
        return this;
    }

    public CvssV2 availability(CIA a) {
        this.a = Objects.requireNonNull(a);
        return this;
    }

    public CvssV2 exploitability(Exploitability e) {
        this.e = Objects.requireNonNull(e);
        return this;
    }

    public CvssV2 remediationLevel(RemediationLevel rl) {
        this.rl = Objects.requireNonNull(rl);
        return this;
    }

    public CvssV2 reportConfidence(ReportConfidence rc) {
        this.rc = Objects.requireNonNull(rc);
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

    static final class Parser implements us.springett.cvss.Parser<CvssV2> {

        private static final List<String> MANDATORY_METRICS = Arrays.asList(
                "AV", "AC", "Au", "C", "I", "A" // Base metrics.
        );

        @Override
        public CvssV2 parseVector(String vector) {
            if (vector == null || vector.isEmpty()) {
                throw new MalformedVectorException("Vector must not be null or empty");
            }

            vector = vector.replaceAll("^\\(|\\)$", "");

            final String[] segments = vector.split("/");
            if (segments.length < MANDATORY_METRICS.size()) {
                throw new MalformedVectorException(String.format(
                        "Vector must consist of at least %d segments (mandatory metrics %s), but has only %s",
                        MANDATORY_METRICS.size(), String.join(", ", MANDATORY_METRICS), segments.length
                ));
            }

            final CvssV2 cvss = new CvssV2();
            final Set<String> metricsSeen = new HashSet<>();
            for (int i = 0; i < segments.length; i++) {
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
                    case "Au":
                        cvss.authentication(requireNonNull(metric, metricValue, Authentication::fromChar));
                        break;
                    case "C":
                        cvss.confidentiality(requireNonNull(metric, metricValue, CIA::fromChar));
                        break;
                    case "I":
                        cvss.integrity(requireNonNull(metric, metricValue, CIA::fromChar));
                        break;
                    case "A":
                        cvss.availability(requireNonNull(metric, metricValue, CIA::fromChar));
                        break;
                    // Temporal.
                    case "E":
                        cvss.exploitability(requireNonNull(metric, metricParts[1], Exploitability::fromString));
                        break;
                    case "RL":
                        cvss.remediationLevel(requireNonNull(metric, metricParts[1], RemediationLevel::fromString));
                        break;
                    case "RC":
                        cvss.reportConfidence(requireNonNull(metric, metricParts[1], ReportConfidence::fromString));
                        break;
                    // Environmental.
                    case "CDP":
                    case "TD":
                    case "CR":
                    case "IR":
                    case "AR":
                        // TODO: Handle these.
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

    @Override
    public String getName() {
        // Even if CVSS 2 officially does not have a vector prefix, use that syntax for the name for consistency with
        // CVSS 3.
        return "CVSS:2.0";
    }

    /**
     * {@inheritDoc}
     */
    public String getVector() {
        final List<String> vectorParts = new ArrayList<>(Arrays.asList(
                "AV:" + av.shorthand,
                "AC:" + ac.shorthand,
                "Au:" + au.shorthand,
                "C:" + c.shorthand,
                "I:" + i.shorthand,
                "A:" + a.shorthand
        ));

        if (e != Exploitability.NOT_DEFINED) {
            vectorParts.add("E:" + e.shorthand);
        }
        if (rl != RemediationLevel.NOT_DEFINED) {
            vectorParts.add("RL:" + rl.shorthand);
        }
        if (rc != ReportConfidence.NOT_DEFINED) {
            vectorParts.add("RC:" + rc.shorthand);
        }

        return "(" + String.join("/", vectorParts) + ")";
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
