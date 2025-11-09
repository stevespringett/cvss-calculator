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
 * Maximum severity distances in EQ MacroVectors for CVSS v4.0 interpolation.
 * <p>
 * Source: <a href="https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/max_severity.js">https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/max_severity.js</a>
 *
 * @author Jeremy Long
 * @since 1.5.0
 */
final class CvssV4MaxSeverity {

    static int getMaxSeverity(String eq, int value) {
        switch (eq) {
            case "eq1":
                return getEq1(value);
            case "eq2":
                return getEq2(value);
            case "eq4":
                return getEq4(value);
            case "eq5":
                return getEq5(value);
            default:
                throw new IllegalArgumentException("Invalid EQ: " + eq);
        }
    }

    static int getMaxSeverityEq3Eq6(int eq3, int eq6) {
        if (eq3 == 0 && eq6 == 0) {
            return 7;
        } else if (eq3 == 0 && eq6 == 1) {
            return 6;
        } else if (eq3 == 1 && eq6 == 0) {
            return 8;
        } else if (eq3 == 1 && eq6 == 1) {
            return 8;
        } else if (eq3 == 2 && eq6 == 1) {
            return 10;
        }
        return 0;
    }

    private static int getEq1(int value) {
        switch (value) {
            case 0:
                return 1;
            case 1:
                return 4;
            case 2:
                return 5;
            default:
                throw new IllegalArgumentException("Invalid eq1 value: " + value);
        }
    }

    private static int getEq2(int value) {
        switch (value) {
            case 0:
                return 1;
            case 1:
                return 2;
            default:
                throw new IllegalArgumentException("Invalid eq2 value: " + value);
        }
    }

    private static int getEq4(int value) {
        switch (value) {
            case 0:
                return 6;
            case 1:
                return 5;
            case 2:
                return 4;
            default:
                throw new IllegalArgumentException("Invalid eq4 value: " + value);
        }
    }

    private static int getEq5(int value) {
        switch (value) {
            case 0:
            case 1:
            case 2:
                return 1;
            default:
                throw new IllegalArgumentException("Invalid eq5 value: " + value);
        }
    }

    private CvssV4MaxSeverity() {
    }
}
