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

import java.util.HashMap;
import java.util.Map;

/**
 * Max composed vectors for CVSS v4.0 severity distance calculations.
 * Defines the highest severity vector for each EQ at each level.
 * <p>
 * Source: <a href="https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/max_composed.js">https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/max_composed.js</a>
 *
 * @author Jeremy Long
 * @since 1.5.0
 */
final class CvssV4MaxComposed {

    private static final Map<String, String[]> EQ1_MAX = new HashMap<>();
    private static final Map<String, String[]> EQ2_MAX = new HashMap<>();
    private static final Map<String, String[]> EQ3EQ6_MAX = new HashMap<>();
    private static final Map<String, String[]> EQ4_MAX = new HashMap<>();
    private static final Map<String, String[]> EQ5_MAX = new HashMap<>();

    static {
        // EQ1
        EQ1_MAX.put("0", new String[]{"AV:N/PR:N/UI:N/"});
        EQ1_MAX.put("1", new String[]{"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"});
        EQ1_MAX.put("2", new String[]{"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"});

        // EQ2
        EQ2_MAX.put("0", new String[]{"AC:L/AT:N/"});
        EQ2_MAX.put("1", new String[]{"AC:H/AT:N/", "AC:L/AT:P/"});

        // EQ3+EQ6 (combined key: eq3 + eq6)
        EQ3EQ6_MAX.put("00", new String[]{"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"});
        EQ3EQ6_MAX.put("01", new String[]{"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"});
        EQ3EQ6_MAX.put("10", new String[]{"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"});
        EQ3EQ6_MAX.put("11", new String[]{"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"});
        EQ3EQ6_MAX.put("21", new String[]{"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"});

        // EQ4
        EQ4_MAX.put("0", new String[]{"SC:H/SI:S/SA:S/"});
        EQ4_MAX.put("1", new String[]{"SC:H/SI:H/SA:H/"});
        EQ4_MAX.put("2", new String[]{"SC:L/SI:L/SA:L/"});

        // EQ5
        EQ5_MAX.put("0", new String[]{"E:A/"});
        EQ5_MAX.put("1", new String[]{"E:P/"});
        EQ5_MAX.put("2", new String[]{"E:U/"});
    }

    static String[] getMaxVectorsForEQ1(int eq1) {
        return EQ1_MAX.get(String.valueOf(eq1));
    }

    static String[] getMaxVectorsForEQ2(int eq2) {
        return EQ2_MAX.get(String.valueOf(eq2));
    }

    static String[] getMaxVectorsForEQ3EQ6(int eq3, int eq6) {
        return EQ3EQ6_MAX.get(String.valueOf(eq3) + eq6);
    }

    static String[] getMaxVectorsForEQ4(int eq4) {
        return EQ4_MAX.get(String.valueOf(eq4));
    }

    private CvssV4MaxComposed() {
    }
}
