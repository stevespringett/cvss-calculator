package us.springett.cvss;

public class CvssV3_1 extends CvssV3 {
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
        int integerInput = (int) (d * 100000);
        if ((integerInput % 10000) == 0) {
            return integerInput / 100000.0;
        } else {
            return Math.floor((double)(integerInput / 10000) + 1) / 10.0;
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
                                "RC:" + rc.shorthand) : "");
    }
}
