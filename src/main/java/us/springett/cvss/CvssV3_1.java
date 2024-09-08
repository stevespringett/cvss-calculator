package us.springett.cvss;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static us.springett.cvss.Parser.requireNonNull;

public class CvssV3_1 extends CvssV3 {

    static final String VECTOR_PREFIX = "CVSS:3.1";

    /**** Environmental Score Metric Group ****/
    protected ModifiedAttackVector mav = ModifiedAttackVector.NOT_DEFINED;
    protected ModifiedAttackComplexity mac = ModifiedAttackComplexity.NOT_DEFINED;
    protected ModifiedPrivilegesRequired mpr = ModifiedPrivilegesRequired.NOT_DEFINED;
    protected ModifiedUserInteraction mui = ModifiedUserInteraction.NOT_DEFINED;
    protected ModifiedScope ms = ModifiedScope.NOT_DEFINED;
    protected ModifiedCIA mc = ModifiedCIA.NOT_DEFINED;
    protected ModifiedCIA mi = ModifiedCIA.NOT_DEFINED;
    protected ModifiedCIA ma = ModifiedCIA.NOT_DEFINED;

    protected ConfidentialityRequirement cr = ConfidentialityRequirement.NOT_DEFINED;
    protected IntegrityRequirement ir = IntegrityRequirement.NOT_DEFINED;
    protected AvailabilityRequirement ar = AvailabilityRequirement.NOT_DEFINED;

    @Override
    public CvssV3_1 attackVector(AttackVector av) {
        this.av = Objects.requireNonNull(av);
        return this;
    }

    @Override
    public CvssV3_1 attackComplexity(AttackComplexity ac) {
        this.ac = Objects.requireNonNull(ac);
        return this;
    }

    @Override
    public CvssV3_1 privilegesRequired(PrivilegesRequired pr) {
        this.pr = Objects.requireNonNull(pr);
        return this;
    }

    @Override
    public CvssV3_1 userInteraction(UserInteraction ui) {
        this.ui = Objects.requireNonNull(ui);
        return this;
    }

    @Override
    public CvssV3_1 scope(Scope s) {
        this.s = Objects.requireNonNull(s);
        return this;
    }

    @Override
    public CvssV3_1 confidentiality(CIA c) {
        this.c = Objects.requireNonNull(c);
        return this;
    }

    @Override
    public CvssV3_1 integrity(CIA i) {
        this.i = Objects.requireNonNull(i);
        return this;
    }

    @Override
    public CvssV3_1 availability(CIA a) {
        this.a = Objects.requireNonNull(a);
        return this;
    }

    @Override
    public CvssV3_1 exploitability(Exploitability e) {
        this.e = Objects.requireNonNull(e);
        return this;
    }

    @Override
    public CvssV3_1 remediationLevel(RemediationLevel rl) {
        this.rl = Objects.requireNonNull(rl);
        return this;
    }

    @Override
    public CvssV3_1 reportConfidence(ReportConfidence rc) {
        this.rc = Objects.requireNonNull(rc);
        return this;
    }

    public CvssV3_1 confidentialityRequirement(ConfidentialityRequirement cr) {
        this.cr = Objects.requireNonNull(cr);
        return this;
    }

    public CvssV3_1 integrityRequirement(IntegrityRequirement ir) {
        this.ir = Objects.requireNonNull(ir);
        return this;
    }

    public CvssV3_1 availabilityRequirement(AvailabilityRequirement ar) {
        this.ar = Objects.requireNonNull(ar);
        return this;
    }

    public CvssV3_1 modifiedAttackVector(ModifiedAttackVector mav) {
        this.mav = Objects.requireNonNull(mav);
        return this;
    }

    public CvssV3_1 modifiedAttackComplexity(ModifiedAttackComplexity mac) {
        this.mac = Objects.requireNonNull(mac);
        return this;
    }

    public CvssV3_1 modifiedPrivilegesRequired(ModifiedPrivilegesRequired mpr) {
        this.mpr = Objects.requireNonNull(mpr);
        return this;
    }

    public CvssV3_1 modifiedUserInteraction(ModifiedUserInteraction mui) {
        this.mui = Objects.requireNonNull(mui);
        return this;
    }

    public CvssV3_1 modifiedScope(ModifiedScope ms) {
        this.ms = Objects.requireNonNull(ms);
        return this;
    }

    public CvssV3_1 modifiedConfidentialityImpact(ModifiedCIA mc) {
        this.mc = Objects.requireNonNull(mc);
        return this;
    }

    public CvssV3_1 modifiedIntegrityImpact(ModifiedCIA mi) {
        this.mi = Objects.requireNonNull(mi);
        return this;
    }

    public CvssV3_1 modifiedAvailabilityImpact(ModifiedCIA ma) {
        this.ma = Objects.requireNonNull(ma);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    public Score calculateScore() {
        // PrivilegesRequired (PR) depends on the value of Scope (S)
        final double prWeight = (Scope.UNCHANGED == s) ? pr.weight : pr.scopeChangedWeight;

        // For metrics that are modified versions of Base Score metrics,
        // use the value of the Base Score metric if the modified version value is "X" ("not defined").
        final double mavWeight = (mav == ModifiedAttackVector.NOT_DEFINED) ? av.weight : mav.weight;
        final double macWeight = (mac == ModifiedAttackComplexity.NOT_DEFINED) ? ac.weight : mac.weight;
        final double muiWeight = (mui == ModifiedUserInteraction.NOT_DEFINED) ? ui.weight : mui.weight;
        final double mcWeight = (mc == ModifiedCIA.NOT_DEFINED) ? c.weight : mc.weight;
        final double miWeight = (mi == ModifiedCIA.NOT_DEFINED) ? i.weight : mi.weight;
        final double maWeight = (ma == ModifiedCIA.NOT_DEFINED) ? a.weight : ma.weight;
        final double msWeight = (ms == ModifiedScope.NOT_DEFINED) ? s.weight : ms.weight;

        // ModifiedPrivilegesRequired (MPR) depends on the value of Modified Scope (MS),
        // or Scope (S) if MS is "X" (not defined).
        final double mprWeight;
        if (ms == ModifiedScope.UNCHANGED || (ms == ModifiedScope.NOT_DEFINED && s == Scope.UNCHANGED)) {
            mprWeight = (mpr == ModifiedPrivilegesRequired.NOT_DEFINED) ? pr.weight : mpr.weight;
        } else {
            mprWeight = (mpr == ModifiedPrivilegesRequired.NOT_DEFINED) ? pr.scopeChangedWeight : mpr.scopeChangedWeight;
        }

        final double impactSubScore = (1 - ((1 - c.weight) * (1 - i.weight) * (1 - a.weight)));
        final double exploitability = exploitabilityCoefficient * av.weight * ac.weight * prWeight * ui.weight;

        final double impact;
        if (s == Scope.UNCHANGED) {
            impact = s.weight * impactSubScore;
        } else {
            impact = s.weight * (impactSubScore - 0.029) - 3.25 * Math.pow((impactSubScore - 0.02), 15);
        }

        final double baseScore;
        if (impact <= 0) {
            baseScore = 0;
        } else {
            if (s == Scope.UNCHANGED) {
                baseScore = roundUp1(Math.min((exploitability + impact), 10));
            } else {
                baseScore = roundUp1(Math.min((scopeCoefficient * (exploitability + impact)), 10));
            }
        }

        final double temporalScore = roundUp1(baseScore * e.weight * rl.weight * rc.weight);

        final double modifiedImpactSubScore = Math.min(1 - ((1 - mcWeight * cr.weight) * (1 - miWeight * ir.weight) * (1 - maWeight * ar.weight)), 0.915);
        final double modifiedExploitability = exploitabilityCoefficient * mavWeight * macWeight * mprWeight * muiWeight;

        final double modifiedImpact;
        if (ms == ModifiedScope.UNCHANGED || (ms == ModifiedScope.NOT_DEFINED && s == Scope.UNCHANGED)) {
            modifiedImpact = msWeight * modifiedImpactSubScore;
        } else {
            modifiedImpact = msWeight * (modifiedImpactSubScore - 0.029) - 3.25 * Math.pow((modifiedImpactSubScore * 0.9731 - 0.02), 13);
        }

        final double envScore;
        if (modifiedImpact <= 0) {
            envScore = 0;
        } else if (ms == ModifiedScope.UNCHANGED || (ms == ModifiedScope.NOT_DEFINED && s == Scope.UNCHANGED)) {
            envScore = roundUp1(roundUp1(Math.min((modifiedImpact + modifiedExploitability), 10)) * e.weight * rl.weight * rc.weight);
        } else {
            envScore = roundUp1(roundUp1(Math.min(scopeCoefficient * (modifiedImpact + modifiedExploitability), 10)) * e.weight * rl.weight * rc.weight);
        }

        return new Score(
                roundNearestTenth(baseScore),
                roundNearestTenth(impact),
                roundNearestTenth(exploitability),
                roundNearestTenth(temporalScore),
                roundNearestTenth(envScore),
                roundNearestTenth(modifiedImpact)
        );
    }

    private double roundUp1(double d) {
        int integerInput = (int) (d * 100000);
        if ((integerInput % 10000) == 0) {
            return integerInput / 100000.0;
        } else {
            return Math.floor((double) (integerInput / 10000) + 1) / 10.0;
        }
    }

    @Override
    public String getName() {
        return VECTOR_PREFIX;
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

        if (e != Exploitability.NOT_DEFINED) {
            vectorParts.add("E:" + e.shorthand);
        }
        if (rl != RemediationLevel.NOT_DEFINED) {
            vectorParts.add("RL:" + rl.shorthand);
        }
        if (rc != ReportConfidence.NOT_DEFINED) {
            vectorParts.add("RC:" + rc.shorthand);
        }

        if (cr != ConfidentialityRequirement.NOT_DEFINED) {
            vectorParts.add("CR:" + cr.shorthand);
        }
        if (ir != IntegrityRequirement.NOT_DEFINED) {
            vectorParts.add("IR:" + ir.shorthand);
        }
        if (ar != AvailabilityRequirement.NOT_DEFINED) {
            vectorParts.add("AR:" + ar.shorthand);
        }
        if (mav != ModifiedAttackVector.NOT_DEFINED) {
            vectorParts.add("MAV:" + mav.shorthand);
        }
        if (mac != ModifiedAttackComplexity.NOT_DEFINED) {
            vectorParts.add("MAC:" + mac.shorthand);
        }
        if (mpr != ModifiedPrivilegesRequired.NOT_DEFINED) {
            vectorParts.add("MPR:" + mpr.shorthand);
        }
        if (mui != ModifiedUserInteraction.NOT_DEFINED) {
            vectorParts.add("MUI:" + mui.shorthand);
        }
        if (ms != ModifiedScope.NOT_DEFINED) {
            vectorParts.add("MS:" + ms.shorthand);
        }
        if (mc != ModifiedCIA.NOT_DEFINED) {
            vectorParts.add("MC:" + mc.shorthand);
        }
        if (mi != ModifiedCIA.NOT_DEFINED) {
            vectorParts.add("MI:" + mi.shorthand);
        }
        if (ma != ModifiedCIA.NOT_DEFINED) {
            vectorParts.add("MA:" + ma.shorthand);
        }

        return String.join("/", vectorParts);
    }

    public ModifiedAttackVector getModifiedAttackVector() {
        return mav;
    }

    public ModifiedAttackComplexity getModifiedAttackComplexity() {
        return mac;
    }

    public ModifiedPrivilegesRequired getModifiedPrivilegesRequired() {
        return mpr;
    }

    public ModifiedUserInteraction getModifiedUserInteraction() {
        return mui;
    }

    public ModifiedScope getModifiedScope() {
        return ms;
    }

    public ModifiedCIA getModifiedConfidentialityImpact() {
        return mc;
    }

    public ModifiedCIA getModifiedIntegrityImpact() {
        return mi;
    }

    public ModifiedCIA getModifiedAvailabilityImpact() {
        return ma;
    }

    public ConfidentialityRequirement getConfidentialityRequirement() {
        return cr;
    }

    public IntegrityRequirement getIntegrityRequirement() {
        return ir;
    }

    public AvailabilityRequirement getAvailabilityRequirement() {
        return ar;
    }

    public enum ConfidentialityRequirement {
        NOT_DEFINED(1.0, 'X'),
        LOW(0.5, 'L'),
        MEDIUM(1.0, 'M'),
        HIGH(1.5, 'H');

        protected final double weight;
        protected final char shorthand;

        ConfidentialityRequirement(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ConfidentialityRequirement fromChar(char c) {
            for (ConfidentialityRequirement cr : ConfidentialityRequirement.values()) {
                if (cr.shorthand==c) {
                    return cr;
                }
            }
            return null;
        }
    }

    public enum IntegrityRequirement {
        NOT_DEFINED(1.0, 'X'),
        LOW(0.5, 'L'),
        MEDIUM(1.0, 'M'),
        HIGH(1.5, 'H');

        protected final double weight;
        protected final char shorthand;

        IntegrityRequirement(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static IntegrityRequirement fromChar(char c) {
            for (IntegrityRequirement ir : IntegrityRequirement.values()) {
                if (ir.shorthand==c) {
                    return ir;
                }
            }
            return null;
        }
    }

    public enum AvailabilityRequirement {
        NOT_DEFINED(1.0, 'X'),
        LOW(0.5, 'L'),
        MEDIUM(1.0, 'M'),
        HIGH(1.5, 'H');

        protected final double weight;
        protected final char shorthand;

        AvailabilityRequirement(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static AvailabilityRequirement fromChar(char c) {
            for (AvailabilityRequirement ar : AvailabilityRequirement.values()) {
                if (ar.shorthand==c) {
                    return ar;
                }
            }
            return null;
        }
    }

    public enum ModifiedAttackVector {
        NOT_DEFINED(0.0, 'X'),
        NETWORK(0.85, 'N'),
        ADJACENT(0.62, 'A'),
        LOCAL(0.55, 'L'),
        PHYSICAL(0.2, 'P');

        protected final double weight;
        protected final char shorthand;

        ModifiedAttackVector(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedAttackVector fromChar(char c) {
            for (ModifiedAttackVector e : ModifiedAttackVector.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedAttackComplexity {
        NOT_DEFINED(0.0, 'X'),
        LOW(0.77, 'L'),
        HIGH(0.44, 'H');

        protected final double weight;
        protected final char shorthand;

        ModifiedAttackComplexity(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedAttackComplexity fromChar(char c) {
            for (ModifiedAttackComplexity e : ModifiedAttackComplexity.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedPrivilegesRequired {
        NOT_DEFINED(0.0, 0.0, 'X'),
        NONE(0.85, 0.85, 'N'),
        LOW(0.62, 0.68, 'L'),
        HIGH(0.27, 0.5, 'H');

        protected final double weight;
        protected final double scopeChangedWeight;
        protected final char shorthand;

        ModifiedPrivilegesRequired(double weight, double scopeChangedWeight, char shorthand) {
            this.weight = weight;
            this.scopeChangedWeight = scopeChangedWeight;
            this.shorthand = shorthand;
        }

        public static ModifiedPrivilegesRequired fromChar(char c) {
            for (ModifiedPrivilegesRequired e : ModifiedPrivilegesRequired.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedUserInteraction {
        NOT_DEFINED(0.0, 'X'),
        NONE(0.85, 'N'),
        REQUIRED(0.62, 'R');

        protected final double weight;
        protected final char shorthand;

        ModifiedUserInteraction(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedUserInteraction fromChar(char c) {
            for (ModifiedUserInteraction e : ModifiedUserInteraction.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedScope {
        NOT_DEFINED(0.0, 'X'),
        UNCHANGED(6.42, 'U'),
        CHANGED(7.52, 'C');

        protected final double weight;
        protected final char shorthand;

        ModifiedScope(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedScope fromChar(char c) {
            for (ModifiedScope e : ModifiedScope.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedCIA {
        NOT_DEFINED(0.0, 'X'),
        NONE(0.0, 'N'),
        LOW(0.22, 'L'),
        HIGH(0.56, 'H');

        protected final double weight;
        protected final char shorthand;

        ModifiedCIA(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedCIA fromChar(char c) {
            for (ModifiedCIA e : ModifiedCIA.values()) {
                if (e.shorthand==c) {
                    return e;
                }
            }
            return null;
        }
    }

    static final class Parser implements us.springett.cvss.Parser<CvssV3_1> {

        private static final List<String> MANDATORY_METRICS = Arrays.asList(
                "AV", "AC", "PR", "UI", "S", "C", "I", "A" // Base metrics.
        );

        @Override
        public CvssV3_1 parseVector(final String vector) {
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
                throw new MalformedVectorException("Missing \"" + VECTOR_PREFIX + "\" prefix");
            }

            final CvssV3_1 cvss = new CvssV3_1();
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
                        cvss.confidentialityRequirement(requireNonNull(metric, metricValue, ConfidentialityRequirement::fromChar));
                        break;
                    case "IR":
                        cvss.integrityRequirement(requireNonNull(metric, metricValue, IntegrityRequirement::fromChar));
                        break;
                    case "AR":
                        cvss.availabilityRequirement(requireNonNull(metric, metricValue, AvailabilityRequirement::fromChar));
                        break;
                    case "MAV":
                        cvss.modifiedAttackVector(requireNonNull(metric, metricValue, ModifiedAttackVector::fromChar));
                        break;
                    case "MAC":
                        cvss.modifiedAttackComplexity(requireNonNull(metric, metricValue, ModifiedAttackComplexity::fromChar));
                        break;
                    case "MPR":
                        cvss.modifiedPrivilegesRequired(requireNonNull(metric, metricValue, ModifiedPrivilegesRequired::fromChar));
                        break;
                    case "MUI":
                        cvss.modifiedUserInteraction(requireNonNull(metric, metricValue, ModifiedUserInteraction::fromChar));
                        break;
                    case "MS":
                        cvss.modifiedScope(requireNonNull(metric, metricValue, ModifiedScope::fromChar));
                        break;
                    case "MC":
                        cvss.modifiedConfidentialityImpact(requireNonNull(metric, metricValue, ModifiedCIA::fromChar));
                        break;
                    case "MI":
                        cvss.modifiedIntegrityImpact(requireNonNull(metric, metricValue, ModifiedCIA::fromChar));
                        break;
                    case "MA":
                        cvss.modifiedAvailabilityImpact(requireNonNull(metric, metricValue, ModifiedCIA::fromChar));
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

}
