package us.springett.cvss;

import java.util.ArrayList;
import java.util.List;

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
        /* GATHER WEIGHTS FOR ALL CONDITIONAL METRICS */

        // PrivilegesRequired (PR) depends on the value of Scope (S)
        final double prWeight = (Scope.UNCHANGED == s) ? pr.weight : pr.scopeChangedWeight;

        // for metrics that are modified versions of Base Score metrics use the value of the Base Score metric if the
        // modified version value is "X" ("not defined")
        final double mavWeight = (mav.shorthand.equalsIgnoreCase("X")) ? av.weight : mav.weight;
        final double macWeight = (mac.shorthand.equalsIgnoreCase("X")) ? ac.weight : mac.weight;
        final double muiWeight = (mui.shorthand.equalsIgnoreCase("X")) ? ui.weight : mui.weight;
        final double mcWeight = (mc.shorthand.equalsIgnoreCase("X")) ? c.weight : mc.weight;
        final double miWeight = (mi.shorthand.equalsIgnoreCase("X")) ? i.weight : mi.weight;
        final double maWeight = (ma.shorthand.equalsIgnoreCase("X")) ? a.weight : ma.weight;
        final double msWeight = (ms.shorthand.equalsIgnoreCase("X")) ? s.weight : ms.weight;

        // ModifiedPrivilegesRequired (MPR) depends on the value of Modified Scope (MS) or Scope (S) if MS is "X" (not defined)
        final double mprWeight;
        if (ms == ModifiedScope.UNCHANGED || (ms == ModifiedScope.NOT_DEFINED && s == Scope.UNCHANGED)) {
            mprWeight = (mpr.shorthand.equalsIgnoreCase("X")) ? pr.weight : mpr.weight;
        } else {
            mprWeight = (mpr.shorthand.equalsIgnoreCase("X")) ? pr.scopeChangedWeight : mpr.scopeChangedWeight;
        }

        /* CALCULATE THE CVSS SCORE */

        // Base Score
        final double impactSubScore = (1 - ((1 - c.weight) * (1 - i.weight) * (1 - a.weight)));
        final double exploitability = exploitabilityCoefficient * av.weight * ac.weight * prWeight * ui.weight;
        final double impact;
        final double baseScore;

        if (s == Scope.UNCHANGED) {
            impact = s.weight * impactSubScore;
        } else {
            impact = s.weight * (impactSubScore - 0.029) - 3.25 * Math.pow((impactSubScore - 0.02), 15);
        }

        if (impact <= 0) {
            baseScore = 0;
        } else {
            if (s == Scope.UNCHANGED) {
                baseScore = roundUp1(Math.min((exploitability + impact), 10));
            } else {
                baseScore = roundUp1(Math.min((scopeCoefficient * (exploitability + impact)), 10));
            }
        }

        // Temporal Score
        final double temporalScore = roundUp1(baseScore * e.weight * rl.weight * rc.weight);

        // Environmental Score
        // - *modifiedExploitability* and *modifiedImpact* recalculate the Base Score exploitability/impact using any
        //   modified values from the Environmental metrics in place of the values specified in the Base Score (if any
        //   have been defined - otherwise the Base Score values are used)
        //   have been defined - otherwise the Base Score values are used)
        final double modifiedImpactSubScore = Math.min(1 - ((1 - mcWeight * cr.weight) * (1 - miWeight * ir.weight) * (1 - maWeight * ar.weight)), 0.915);
        final double modifiedExploitability = exploitabilityCoefficient * mavWeight * macWeight * mprWeight * muiWeight;
        final double modifiedImpact;
        final double envScore;

        if (ms == ModifiedScope.UNCHANGED || (ms == ModifiedScope.NOT_DEFINED && s == Scope.UNCHANGED)) {
            modifiedImpact = msWeight * modifiedImpactSubScore;
        } else {
            modifiedImpact = msWeight * (modifiedImpactSubScore - 0.029) - 3.25 * Math.pow((modifiedImpactSubScore * 0.9731 - 0.02), 13);
        }

        if (modifiedImpact <= 0) {
            envScore = 0;
        } else if (ms == ModifiedScope.UNCHANGED || (ms == ModifiedScope.NOT_DEFINED && s == Scope.UNCHANGED)) {
            envScore = roundUp1(roundUp1(Math.min((modifiedImpact + modifiedExploitability), 10)) * e.weight * rl.weight * rc.weight);
        } else {
            envScore = roundUp1(roundUp1(Math.min(scopeCoefficient * (modifiedImpact + modifiedExploitability), 10)) * e.weight * rl.weight * rc.weight);
        }

        return new Score(roundNearestTenth(baseScore), roundNearestTenth(impact), roundNearestTenth(exploitability), roundNearestTenth(temporalScore), roundNearestTenth(envScore), roundNearestTenth(modifiedImpact));
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
        List<String> vector = new ArrayList<>();
        vector.add("CVSS:3.1");

        if (av != null) vector.add("AV:" + av.shorthand);
        if (ac != null) vector.add("AC:" + ac.shorthand);
        if (pr != null) vector.add("PR:" + pr.shorthand);
        if (ui != null) vector.add("UI:" + ui.shorthand);
        if (s != null) vector.add("S:" + s.shorthand);
        if (c != null) vector.add("C:" + c.shorthand);
        if (i != null) vector.add("I:" + i.shorthand);
        if (a != null) vector.add("A:" + a.shorthand);

        if (e != null && (!e.shorthand.equalsIgnoreCase("X"))) vector.add("E:" + e.shorthand);
        if (rl != null && (!rl.shorthand.equalsIgnoreCase("X"))) vector.add("RL:" + rl.shorthand);
        if (rc != null && (!rc.shorthand.equalsIgnoreCase("X"))) vector.add("RC:" + rc.shorthand);

        if (cr != null && (!cr.shorthand.equalsIgnoreCase("X"))) vector.add("CR:" + cr.shorthand);
        if (ir != null && (!ir.shorthand.equalsIgnoreCase("X"))) vector.add("IR:" + ir.shorthand);
        if (ar != null && (!ar.shorthand.equalsIgnoreCase("X"))) vector.add("AR:" + ar.shorthand);
        if (mav != null && (!mav.shorthand.equalsIgnoreCase("X"))) vector.add("MAV:" + mav.shorthand);
        if (mac != null && (!mac.shorthand.equalsIgnoreCase("X"))) vector.add("MAC:" + mac.shorthand);
        if (mpr != null && (!mpr.shorthand.equalsIgnoreCase("X"))) vector.add("MPR:" + mpr.shorthand);
        if (mui != null && (!mui.shorthand.equalsIgnoreCase("X"))) vector.add("MUI:" + mui.shorthand);
        if (ms != null && (!ms.shorthand.equalsIgnoreCase("X"))) vector.add("MS:" + ms.shorthand);
        if (mc != null && (!mc.shorthand.equalsIgnoreCase("X"))) vector.add("MC:" + mc.shorthand);
        if (mi != null && (!mi.shorthand.equalsIgnoreCase("X"))) vector.add("MI:" + mi.shorthand);
        if (ma != null && (!ma.shorthand.equalsIgnoreCase("X"))) vector.add("MA:" + ma.shorthand);

        return String.join("/", vector);
    }

    /**
     * Return the vector string of the {@link CvssV3_1}.
     *
     * @param includeAll includes all NOT_DEFINED fields in the vector string if true, removes them if false
     * @return the vector string of the {@link CvssV3_1}
     */
    public String getVector(final boolean includeAll) {
        if (includeAll) {
            List<String> vector = new ArrayList<>();
            vector.add("CVSS:3.1");
            if (av != null) vector.add("AV:" + av.shorthand);
            if (ac != null) vector.add("AC:" + ac.shorthand);
            if (pr != null) vector.add("PR:" + pr.shorthand);
            if (ui != null) vector.add("UI:" + ui.shorthand);
            if (s != null) vector.add("S:" + s.shorthand);
            if (c != null) vector.add("C:" + c.shorthand);
            if (i != null) vector.add("I:" + i.shorthand);
            if (a != null) vector.add("A:" + a.shorthand);

            if (e != null) vector.add("E:" + e.shorthand);
            if (rl != null) vector.add("RL:" + rl.shorthand);
            if (rc != null) vector.add("RC:" + rc.shorthand);

            if (cr != null) vector.add("CR:" + cr.shorthand);
            if (ir != null) vector.add("IR:" + ir.shorthand);
            if (ar != null) vector.add("AR:" + ar.shorthand);
            if (mav != null) vector.add("MAV:" + mav.shorthand);
            if (mac != null) vector.add("MAC:" + mac.shorthand);
            if (mpr != null) vector.add("MPR:" + mpr.shorthand);
            if (mui != null) vector.add("MUI:" + mui.shorthand);
            if (ms != null) vector.add("MS:" + ms.shorthand);
            if (mc != null) vector.add("MC:" + mc.shorthand);
            if (mi != null) vector.add("MI:" + mi.shorthand);
            if (ma != null) vector.add("MA:" + ma.shorthand);
            return String.join("/", vector);
        }
        return getVector();
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
                if (cr.shorthand.equalsIgnoreCase(text)) {
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
                if (ir.shorthand.equalsIgnoreCase(text)) {
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
                if (ar.shorthand.equalsIgnoreCase(text)) {
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
                if (e.shorthand.equalsIgnoreCase(text)) {
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
                if (e.shorthand.equalsIgnoreCase(text)) {
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
                if (e.shorthand.equalsIgnoreCase(text)) {
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
                if (e.shorthand.equalsIgnoreCase(text)) {
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
                if (e.shorthand.equalsIgnoreCase(text)) {
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
                if (e.shorthand.equalsIgnoreCase(text)) {
                    return e;
                }
            }
            return null;
        }
    }
}
