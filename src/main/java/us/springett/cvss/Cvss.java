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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Defines an interface for CVSS versions.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public interface Cvss {

    String V2_PATTERN = "AV:(N|A|L)\\/AC:(L|M|H)\\/A[Uu]:(N|S|M)\\/C:(N|P|C)\\/I:(N|P|C)\\/A:(N|P|C)";
    String V2_TEMPORAL = "\\/E:\\b(F|H|U|POC|ND)\\b\\/RL:\\b(W|U|TF|OF|ND)\\b\\/RC:\\b(C|UR|UC|ND)\\b";

    String V3_PATTERN = "AV:(N|A|L|P)\\/AC:(L|H)\\/PR:(N|L|H)\\/UI:(N|R)\\/S:(U|C)\\/C:(N|L|H)\\/I:(N|L|H)\\/A:(N|L|H)";
    String V3_TEMPORAL = "\\/E:(F|H|U|P|X)\\/RL:(W|U|T|O|X)\\/RC:(C|R|U|X)";
    String V3_1_ENVIRONMENTAL = "\\/CR:(X|L|M|H)\\/IR:(X|L|M|H)\\/AR:(X|L|M|H)\\/MAV:(X|N|A|L|P)\\/MAC:(X|L|H)\\/MPR:(X|N|L|H)\\/MUI:(X|N|R)\\/MS:(X|U|C)\\/MC:(X|N|L|H)\\/MI:(X|N|L|H)\\/MA:(X|N|L|H)";

    Pattern CVSSv2_PATTERN = Pattern.compile(V2_PATTERN);
    Pattern CVSSv2_PATTERN_TEMPORAL = Pattern.compile(V2_PATTERN + V2_TEMPORAL);
    Pattern CVSSv3_PATTERN = Pattern.compile(V3_PATTERN);
    Pattern CVSSv3_PATTERN_TEMPORAL = Pattern.compile(V3_PATTERN + V3_TEMPORAL);
    Pattern CVSSv3_1_PATTERN = Pattern.compile(V3_PATTERN + V3_TEMPORAL + V3_1_ENVIRONMENTAL);

    /**
     * A factory method which accepts a String representation of a
     * CVSS vector, determines which CVSS version it is, and returns
     * the corresponding CVSS object. If the vector is invalid, a
     * null value will be returned.
     *
     * @param vector the CVSS vector to parse
     * @return a Cvss object
     * @since 1.1.0
     */
    static Cvss fromVector(String vector) {
        if (vector == null) {
            return null;
        }

        Matcher v3_1Matcher = CVSSv3_1_PATTERN.matcher(vector);
        if (v3_1Matcher.find()) {
            // Found a valid CVSSv3.1 vector
            char [] vectorChars = vector.toCharArray();
            CvssV3_1 cvssV3_1 = getCvssV3_1BaseVector(v3_1Matcher, vectorChars);
            fillV3TemporalValues(v3_1Matcher, vectorChars, cvssV3_1);
            cvssV3_1.confidentialityRequirement(CvssV3_1.ConfidentialityRequirement.fromChar(vectorChars[v3_1Matcher.start(12)]));
            cvssV3_1.integrityRequirement(CvssV3_1.IntegrityRequirement.fromChar(vectorChars[v3_1Matcher.start(13)]));
            cvssV3_1.availabilityRequirement(CvssV3_1.AvailabilityRequirement.fromChar(vectorChars[v3_1Matcher.start(14)]));
            cvssV3_1.modifiedAttackVector(CvssV3_1.ModifiedAttackVector.fromChar(vectorChars[v3_1Matcher.start(15)]));
            cvssV3_1.modifiedAttackComplexity(CvssV3_1.ModifiedAttackComplexity.fromChar(vectorChars[v3_1Matcher.start(16)]));
            cvssV3_1.modifiedPrivilegesRequired(CvssV3_1.ModifiedPrivilegesRequired.fromChar(vectorChars[v3_1Matcher.start(17)]));
            cvssV3_1.modifiedUserInteraction(CvssV3_1.ModifiedUserInteraction.fromChar(vectorChars[v3_1Matcher.start(18)]));
            cvssV3_1.modifiedScope(CvssV3_1.ModifiedScope.fromChar(vectorChars[v3_1Matcher.start(19)]));
            cvssV3_1.modifiedConfidentialityImpact(CvssV3_1.ModifiedCIA.fromChar(vectorChars[v3_1Matcher.start(20)]));
            cvssV3_1.modifiedIntegrityImpact(CvssV3_1.ModifiedCIA.fromChar(vectorChars[v3_1Matcher.start(21)]));
            cvssV3_1.modifiedAvailabilityImpact(CvssV3_1.ModifiedCIA.fromChar(vectorChars[v3_1Matcher.start(22)]));
            return cvssV3_1;
        }
        Matcher v3TemporalMatcher = CVSSv3_PATTERN_TEMPORAL.matcher(vector);
        if (v3TemporalMatcher.find()) {
            char [] vectorChars = vector.toCharArray();
            // Found a valid CVSSv3 vector with temporal values
            CvssV3 cvssV3 = getCvssV3BaseVector(v3TemporalMatcher, vectorChars);
            fillV3TemporalValues(v3TemporalMatcher, vectorChars, cvssV3);
            return cvssV3;
        }
        Matcher v3Matcher = CVSSv3_PATTERN.matcher(vector);
        if (v3Matcher.find()) {
            char [] vectorChars = vector.toCharArray();
            // Found a valid CVSSv3 vector
            return getCvssV3BaseVector(v3Matcher, vectorChars);
        }
        Matcher v2TemporalMatcher = CVSSv2_PATTERN_TEMPORAL.matcher(vector);
        if (v2TemporalMatcher.find()) {
            // Found a valid CVSSv2 vector with temporal values
            CvssV2 cvssV2 = getCvssV2BaseVector(v2TemporalMatcher, vector.toCharArray());
            cvssV2.exploitability(CvssV2.Exploitability.fromString(v2TemporalMatcher.group(7)));
            cvssV2.remediationLevel(CvssV2.RemediationLevel.fromString(v2TemporalMatcher.group(8)));
            cvssV2.reportConfidence(CvssV2.ReportConfidence.fromString(v2TemporalMatcher.group(9)));
            return cvssV2;
        }
        Matcher v2Matcher = CVSSv2_PATTERN.matcher(vector);
        if (v2Matcher.find()) {
            // Found a valid CVSSv2 vector
            return getCvssV2BaseVector(v2Matcher, vector.toCharArray());
        } else
        return null;
    }

    static void fillV3TemporalValues(Matcher v3TemporalMatcher, char[] vectorChars, CvssV3 cvssV3) {
        cvssV3.exploitability(CvssV3.Exploitability.fromChar(vectorChars[v3TemporalMatcher.start(9)]));
        cvssV3.remediationLevel(CvssV3.RemediationLevel.fromChar(vectorChars[v3TemporalMatcher.start(10)]));
        cvssV3.reportConfidence(CvssV3.ReportConfidence.fromChar(vectorChars[v3TemporalMatcher.start(11)]));
    }

    static CvssV2 getCvssV2BaseVector(Matcher st, char [] array) {
        CvssV2 cvssV2 = new CvssV2();
        cvssV2.attackVector(CvssV2.AttackVector.fromChar(array[st.start(1)]));
        cvssV2.attackComplexity(CvssV2.AttackComplexity.fromChar(array[st.start(2)]));
        cvssV2.authentication(CvssV2.Authentication.fromChar(array[st.start(3)]));
        cvssV2.confidentiality(CvssV2.CIA.fromChar(array[st.start(4)]));
        cvssV2.integrity(CvssV2.CIA.fromChar(array[st.start(5)]));
        cvssV2.availability(CvssV2.CIA.fromChar(array[st.start(6)]));
        return cvssV2;
    }

    static CvssV3 getCvssV3BaseVector(Matcher st, char [] array) {
        CvssV3 cvssV3 = new CvssV3();
        cvssV3.attackVector(CvssV3.AttackVector.fromChar(array[st.start(1)]));
        cvssV3.attackComplexity(CvssV3.AttackComplexity.fromChar(array[st.start(2)]));
        cvssV3.privilegesRequired(CvssV3.PrivilegesRequired.fromChar(array[st.start(3)]));
        cvssV3.userInteraction(CvssV3.UserInteraction.fromChar(array[st.start(4)]));
        cvssV3.scope(CvssV3.Scope.fromChar(array[st.start(5)]));
        cvssV3.confidentiality(CvssV3.CIA.fromString(array[st.start(6)]));
        cvssV3.integrity(CvssV3.CIA.fromString(array[st.start(7)]));
        cvssV3.availability(CvssV3.CIA.fromString(array[st.start(8)]));
        return cvssV3;
    }

    static CvssV3_1 getCvssV3_1BaseVector(Matcher st, char [] array) {
        CvssV3_1 cvssV3_1 = new CvssV3_1();
        cvssV3_1.attackVector(CvssV3.AttackVector.fromChar(array[st.start(1)]));
        cvssV3_1.attackComplexity(CvssV3.AttackComplexity.fromChar(array[st.start(2)]));
        cvssV3_1.privilegesRequired(CvssV3.PrivilegesRequired.fromChar(array[st.start(3)]));
        cvssV3_1.userInteraction(CvssV3.UserInteraction.fromChar(array[st.start(4)]));
        cvssV3_1.scope(CvssV3.Scope.fromChar(array[st.start(5)]));
        cvssV3_1.confidentiality(CvssV3.CIA.fromString(array[st.start(6)]));
        cvssV3_1.integrity(CvssV3.CIA.fromString(array[st.start(7)]));
        cvssV3_1.availability(CvssV3.CIA.fromString(array[st.start(8)]));
        return cvssV3_1;
    }

    /**
     * Calculates a CVSS score.
     *
     * @return a Score object
     * @since 1.0.0
     */
    Score calculateScore();

    /**
     * Returns the CVSS vector
     *
     * @return a String of the CVSS vector
     * @since 1.0.0
     */
    String getVector();
}
