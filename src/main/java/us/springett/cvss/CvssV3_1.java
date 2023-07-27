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
        final double prWeight = (Scope.UNCHANGED == s) ? pr.weight : pr.scopeChangedWeight;
        final double mprWeight;

        final double exploitabilitySubScore = exploitabilityCoefficient * av.weight * ac.weight * prWeight * ui.weight;
        final double modifiedExploitabilitySubScore;
        final double impactSubScoreMultiplier = 1 - ((1 - c.weight) * (1 - i.weight) * (1 - a.weight));
        final double modifiedImpactSubScoreMultiplier = Math.min(1 - ((1 - cr.weight * mc.weight) * (1 - ir.weight * mi.weight) * (1 - ar.weight * ma.weight)), 0.915);

        final double baseScore;
        double impactSubScore;
        final double temporalScore;
        final double environmentalScore;
        double modifiedImpactSubScore;

        if (Scope.UNCHANGED == s) {
            impactSubScore = s.weight * impactSubScoreMultiplier;
        } else {
            impactSubScore = s.weight * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15);
        }

        if (impactSubScore <= 0) {
            baseScore = 0;
            impactSubScore = 0;
        } else {
            if (Scope.UNCHANGED == s) {
                baseScore = roundUp1(Math.min((impactSubScore + exploitabilitySubScore), 10));
            } else {
                baseScore = roundUp1(Math.min((impactSubScore + exploitabilitySubScore) * scopeCoefficient, 10));
            }
        }

        temporalScore = roundUp1(baseScore * e.weight * rl.weight * rc.weight);

        boolean mprNotDefined = mpr == ModifiedPrivilegesRequired.NOT_DEFINED;
        if (ModifiedScope.UNCHANGED == ms) {
            mprWeight = mprNotDefined ? pr.weight : mpr.weight;
            modifiedImpactSubScore = ms.weight * modifiedImpactSubScoreMultiplier;
        } else if (ModifiedScope.CHANGED == ms) {
            mprWeight = mprNotDefined ? pr.scopeChangedWeight : mpr.scopeChangedWeight;
            modifiedImpactSubScore = ms.weight * (modifiedImpactSubScoreMultiplier - 0.029) - 3.25 * Math.pow((modifiedImpactSubScoreMultiplier * 0.9731 - 0.02), 13);
        } else {
            if (Scope.UNCHANGED == s){
                mprWeight = mprNotDefined ? pr.weight : mpr.weight;
                modifiedImpactSubScore = s.weight * modifiedImpactSubScoreMultiplier;
            } else {
                mprWeight = mprNotDefined ? pr.scopeChangedWeight : mpr.scopeChangedWeight;
                modifiedImpactSubScore = s.weight * (modifiedImpactSubScoreMultiplier - 0.029) - 3.25 * Math.pow((modifiedImpactSubScoreMultiplier * 0.9731 - 0.02), 13);
            }
//            mprWeight = 0;
//            modifiedImpactSubScore = 0;
        }

        double mavWeight = mav == ModifiedAttackVector.NOT_DEFINED ? av.weight : mav.weight;
        double macWeight = mac == ModifiedAttackComplexity.NOT_DEFINED ? ac.weight : mac.weight;
        double muiWeight = mui == ModifiedUserInteraction.NOT_DEFINED ? ui.weight : mui.weight;
        modifiedExploitabilitySubScore = exploitabilityCoefficient * mavWeight * macWeight * mprWeight * muiWeight;

        if (modifiedImpactSubScore <= 0) {
            environmentalScore = 0;
            modifiedImpactSubScore = 0;
        } else {
            if (ModifiedScope.UNCHANGED == ms || (ModifiedScope.NOT_DEFINED == ms && Scope.UNCHANGED == s)) {
                environmentalScore = roundUp1(roundUp1(Math.min((modifiedImpactSubScore + modifiedExploitabilitySubScore), 10)) * e.weight * rl.weight * rc.weight);
            } else if (ModifiedScope.CHANGED == ms || (ModifiedScope.NOT_DEFINED == ms && Scope.CHANGED == s)) {
                environmentalScore = roundUp1(roundUp1(Math.min(1.08 * (modifiedImpactSubScore + modifiedExploitabilitySubScore), 10)) * e.weight * rl.weight * rc.weight);
            } else {
                // throw new RuntimeException("This should never happen");
                // This should never happen
                environmentalScore = 0;
            }
        }

        return new Score(baseScore, roundNearestTenth(impactSubScore), roundNearestTenth(exploitabilitySubScore), temporalScore, environmentalScore, roundNearestTenth(modifiedImpactSubScore));
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
        NOT_DEFINED(1.0, "X"),
        LOW(0.5, "L"),
        MEDIUM(1.0, "M"),
        HIGH(1.5, "H");

        protected final double weight;
        protected final String shorthand;

        ConfidentialityRequirement(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ConfidentialityRequirement fromString(String text) {
            for (ConfidentialityRequirement cr : ConfidentialityRequirement.values()) {
                if (cr.shorthand.equals(text)) {
                    return cr;
                }
            }
            return null;
        }
    }

    public enum IntegrityRequirement {
        NOT_DEFINED(1.0, "X"),
        LOW(0.5, "L"),
        MEDIUM(1.0, "M"),
        HIGH(1.5, "H");

        protected final double weight;
        protected final String shorthand;

        IntegrityRequirement(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static IntegrityRequirement fromString(String text) {
            for (IntegrityRequirement ir : IntegrityRequirement.values()) {
                if (ir.shorthand.equals(text)) {
                    return ir;
                }
            }
            return null;
        }
    }

    public enum AvailabilityRequirement {
        NOT_DEFINED(1.0, "X"),
        LOW(0.5, "L"),
        MEDIUM(1.0, "M"),
        HIGH(1.5, "H");

        protected final double weight;
        protected final String shorthand;

        AvailabilityRequirement(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static AvailabilityRequirement fromString(String text) {
            for (AvailabilityRequirement ar : AvailabilityRequirement.values()) {
                if (ar.shorthand.equals(text)) {
                    return ar;
                }
            }
            return null;
        }
    }

    public enum ModifiedAttackVector {
        NOT_DEFINED(0.0, "X"),
        NETWORK(0.85, "N"),
        ADJACENT(0.62, "A"),
        LOCAL(0.55, "L"),
        PHYSICAL(0.2, "P");

        protected final double weight;
        protected final String shorthand;

        ModifiedAttackVector(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedAttackVector fromString(String text) {
            for (ModifiedAttackVector e : ModifiedAttackVector.values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedAttackComplexity {
        NOT_DEFINED(0.0, "X"),
        LOW(0.77, "L"),
        HIGH(0.44, "H");

        protected final double weight;
        protected final String shorthand;

        ModifiedAttackComplexity(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedAttackComplexity fromString(String text) {
            for (ModifiedAttackComplexity e : ModifiedAttackComplexity.values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedPrivilegesRequired {
        NOT_DEFINED(0.0, 0.0, "X"),
        NONE(0.85, 0.85, "N"),
        LOW(0.62, 0.68, "L"),
        HIGH(0.27, 0.5, "H");

        protected final double weight;
        protected final double scopeChangedWeight;
        protected final String shorthand;

        ModifiedPrivilegesRequired(double weight, double scopeChangedWeight, String shorthand) {
            this.weight = weight;
            this.scopeChangedWeight = scopeChangedWeight;
            this.shorthand = shorthand;
        }

        public static ModifiedPrivilegesRequired fromString(String text) {
            for (ModifiedPrivilegesRequired e : ModifiedPrivilegesRequired.values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedUserInteraction {
        NOT_DEFINED(0.0, "X"),
        NONE(0.85, "N"),
        REQUIRED(0.62, "R");

        protected final double weight;
        protected final String shorthand;

        ModifiedUserInteraction(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedUserInteraction fromString(String text) {
            for (ModifiedUserInteraction e : ModifiedUserInteraction.values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedScope {
        NOT_DEFINED(0.0, "X"),
        UNCHANGED(6.42, "U"),
        CHANGED(7.52, "C");

        protected final double weight;
        protected final String shorthand;

        ModifiedScope(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedScope fromString(String text) {
            for (ModifiedScope e : ModifiedScope.values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }

    public enum ModifiedCIA {
        NOT_DEFINED(0.0, "X"),
        NONE(0.0, "N"),
        LOW(0.22, "L"),
        HIGH(0.56, "H");

        protected final double weight;
        protected final String shorthand;

        ModifiedCIA(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedCIA fromString(String text) {
            for (ModifiedCIA e : ModifiedCIA.values()) {
                if (e.shorthand.equals(text)) {
                    return e;
                }
            }
            return null;
        }
    }
}
