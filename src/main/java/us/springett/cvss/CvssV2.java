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

    private AttackVector av;
    private AttackComplexity ac;
    private Authentication au;
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

    public enum AttackVector {
        NETWORK(1.0, "N"),
        ADJACENT(0.646, "A"),
        LOCAL(0.395, "L");

        private final double weight;
        private final String shorthand;
        AttackVector(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
    }

    public enum AttackComplexity {
        LOW(0.71, "L"),
        MEDIUM(0.61, "M"),
        HIGH(0.35, "H");

        private final double weight;
        private final String shorthand;
        AttackComplexity(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
    }

    public enum Authentication  {
        NONE(0.704, "N"),
        SINGLE(0.56, "S"),
        MULTIPLE(0.45, "M");

        private final double weight;
        private final String shorthand;
        Authentication(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }
    }

    public enum CIA {
        NONE(0.0, "N"),
        PARTIAL(0.275, "P"),
        COMPLETE(0.660, "C");

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
        final double baseScore;
        final double impactSubScore;
        final double exploitabalitySubScore;

        impactSubScore = 10.41 * (1 - (1 - c.weight) * (1 - i.weight) * (1 - a.weight));
        exploitabalitySubScore = 20 * av.weight * ac.weight * au.weight;
        baseScore = roundNearestTenth(((0.6 * impactSubScore) + (0.4 * exploitabalitySubScore) - 1.5) * f(impactSubScore));

        return new Score(baseScore, roundNearestTenth(impactSubScore), roundNearestTenth(exploitabalitySubScore));
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
                "A:" + a.shorthand + ")";
    }

    @Override
    public String toString() {
        return getVector();
    }
}
