package us.springett.cvss;

public class CvssV3_1 extends CvssV3 {

    /**** Environmental Score Metric Group ****/
    protected ModifiedAttackVector mav;
    protected ModifiedAttackComplexity mac;
    protected ModifiedPrivilegesRequired mpr;
    protected ModifiedUserInteraction mui;
    protected ModifiedScope ms;
    protected ModifiedCIA mc;
    protected ModifiedCIA mi;
    protected ModifiedCIA ma;

    protected ConfidentialityRequirement cr;
    protected IntegrityRequirement ir;
    protected AvailabilityRequirement ar;

    public CvssV3_1 attackVector(AttackVector av) {
        this.av = av;
        return this;
    }

    public CvssV3_1 attackComplexity(AttackComplexity ac) {
        this.ac = ac;
        return this;
    }

    public CvssV3_1 privilegesRequired(PrivilegesRequired pr) {
        this.pr = pr;
        return this;
    }

    public CvssV3_1 userInteraction(UserInteraction ui) {
        this.ui = ui;
        return this;
    }

    public CvssV3_1 scope(Scope s) {
        this.s = s;
        return this;
    }

    public CvssV3_1 confidentiality(CIA c) {
        this.c = c;
        return this;
    }

    public CvssV3_1 integrity(CIA i) {
        this.i = i;
        return this;
    }

    public CvssV3_1 availability(CIA a) {
        this.a = a;
        return this;
    }

    public CvssV3_1 exploitability(Exploitability e) {
        this.e = e;
        return this;
    }

    public CvssV3_1 remediationLevel(RemediationLevel rl) {
        this.rl = rl;
        return this;
    }

    public CvssV3_1 reportConfidence(ReportConfidence rc) {
        this.rc = rc;
        return this;
    }

    public CvssV3_1 confidentialityRequirement(ConfidentialityRequirement cr) {
        this.cr = cr;
        return this;
    }

    public CvssV3_1 integrityRequirement(IntegrityRequirement ir) {
        this.ir = ir;
        return this;
    }

    public CvssV3_1 availabilityRequirement(AvailabilityRequirement ar) {
        this.ar = ar;
        return this;
    }

    public CvssV3_1 modifiedAttackVector(ModifiedAttackVector mav) {
        this.mav = mav;
        return this;
    }

    public CvssV3_1 modifiedAttackComplexity(ModifiedAttackComplexity mac) {
        this.mac = mac;
        return this;
    }

    public CvssV3_1 modifiedPrivilegesRequired(ModifiedPrivilegesRequired mpr) {
        this.mpr = mpr;
        return this;
    }

    public CvssV3_1 modifiedUserInteraction(ModifiedUserInteraction mui) {
        this.mui = mui;
        return this;
    }

    public CvssV3_1 modifiedScope(ModifiedScope ms) {
        this.ms = ms;
        return this;
    }

    public CvssV3_1 modifiedConfidentialityImpact(ModifiedCIA mc) {
        this.mc = mc;
        return this;
    }

    public CvssV3_1 modifiedIntegrityImpact(ModifiedCIA mi) {
        this.mi = mi;
        return this;
    }

    public CvssV3_1 modifiedAvailabilityImpact(ModifiedCIA ma) {
        this.ma = ma;
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

    /**
     * {@inheritDoc}
     */
    public String getVector() {
        return "CVSS:3.1/" +
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
                                "RC:" + rc.shorthand) : "") +
                "/CR:" + cr.shorthand + "/" +
                "IR:" + ir.shorthand + "/" +
                "AR:" + ar.shorthand + "/" +
                "MAV:" + mav.shorthand + "/" +
                "MAC:" + mac.shorthand + "/" +
                "MPR:" + mpr.shorthand + "/" +
                "MUI:" + mui.shorthand + "/" +
                "MS:" + ms.shorthand + "/" +
                "MC:" + mc.shorthand + "/" +
                "MI:" + mi.shorthand + "/" +
                "MA:" + ma.shorthand;
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
}
