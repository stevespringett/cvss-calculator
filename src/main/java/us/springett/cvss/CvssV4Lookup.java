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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * MacroVector lookup table for CVSS v4.0 scoring.
 * Contains 233 MacroVector entries mapping 6-digit keys to scores.
 * <p>
 * Source: <a href="https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js">https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js</a>
 *
 * @author Jeremy Long
 * @since 1.5.0
 */
final class CvssV4Lookup {

    private static final Map<String, Double> LOOKUP_TABLE;

    static {
        Map<String, Double> table = new HashMap<>(233);

        table.put("000000", 10.0);
        table.put("000001", 9.9);
        table.put("000010", 9.8);
        table.put("000011", 9.5);
        table.put("000020", 9.5);
        table.put("000021", 9.2);
        table.put("000100", 10.0);
        table.put("000101", 9.6);
        table.put("000110", 9.3);
        table.put("000111", 8.7);
        table.put("000120", 9.1);
        table.put("000121", 8.1);
        table.put("000200", 9.3);
        table.put("000201", 9.0);
        table.put("000210", 8.9);
        table.put("000211", 8.0);
        table.put("000220", 8.1);
        table.put("000221", 6.8);
        table.put("001000", 9.8);
        table.put("001001", 9.5);
        table.put("001010", 9.5);
        table.put("001011", 9.2);
        table.put("001020", 9.0);
        table.put("001021", 8.4);
        table.put("001100", 9.3);
        table.put("001101", 9.2);
        table.put("001110", 8.9);
        table.put("001111", 8.1);
        table.put("001120", 8.1);
        table.put("001121", 6.5);
        table.put("001200", 8.8);
        table.put("001201", 8.0);
        table.put("001210", 7.8);
        table.put("001211", 7.0);
        table.put("001220", 6.9);
        table.put("001221", 4.8);
        table.put("002001", 9.2);
        table.put("002011", 8.2);
        table.put("002021", 7.2);
        table.put("002101", 7.9);
        table.put("002111", 6.9);
        table.put("002121", 5.0);
        table.put("002201", 6.9);
        table.put("002211", 5.5);
        table.put("002221", 2.7);
        table.put("010000", 9.9);
        table.put("010001", 9.7);
        table.put("010010", 9.5);
        table.put("010011", 9.2);
        table.put("010020", 9.2);
        table.put("010021", 8.5);
        table.put("010100", 9.5);
        table.put("010101", 9.1);
        table.put("010110", 9.0);
        table.put("010111", 8.3);
        table.put("010120", 8.4);
        table.put("010121", 7.1);
        table.put("010200", 9.2);
        table.put("010201", 8.1);
        table.put("010210", 8.2);
        table.put("010211", 7.1);
        table.put("010220", 7.2);
        table.put("010221", 5.3);
        table.put("011000", 9.5);
        table.put("011001", 9.3);
        table.put("011010", 9.2);
        table.put("011011", 8.5);
        table.put("011020", 8.5);
        table.put("011021", 7.3);
        table.put("011100", 9.2);
        table.put("011101", 8.2);
        table.put("011110", 8.0);
        table.put("011111", 7.2);
        table.put("011120", 7.0);
        table.put("011121", 5.9);
        table.put("011200", 8.4);
        table.put("011201", 7.0);
        table.put("011210", 7.1);
        table.put("011211", 5.2);
        table.put("011220", 5.0);
        table.put("011221", 3.0);
        table.put("012001", 8.6);
        table.put("012011", 7.5);
        table.put("012021", 5.2);
        table.put("012101", 7.1);
        table.put("012111", 5.2);
        table.put("012121", 2.9);
        table.put("012201", 6.3);
        table.put("012211", 2.9);
        table.put("012221", 1.7);
        table.put("100000", 9.8);
        table.put("100001", 9.5);
        table.put("100010", 9.4);
        table.put("100011", 8.7);
        table.put("100020", 9.1);
        table.put("100021", 8.1);
        table.put("100100", 9.4);
        table.put("100101", 8.9);
        table.put("100110", 8.6);
        table.put("100111", 7.4);
        table.put("100120", 7.7);
        table.put("100121", 6.4);
        table.put("100200", 8.7);
        table.put("100201", 7.5);
        table.put("100210", 7.4);
        table.put("100211", 6.3);
        table.put("100220", 6.3);
        table.put("100221", 4.9);
        table.put("101000", 9.4);
        table.put("101001", 8.9);
        table.put("101010", 8.8);
        table.put("101011", 7.7);
        table.put("101020", 7.6);
        table.put("101021", 6.7);
        table.put("101100", 8.6);
        table.put("101101", 7.6);
        table.put("101110", 7.4);
        table.put("101111", 5.8);
        table.put("101120", 5.9);
        table.put("101121", 5.0);
        table.put("101200", 7.2);
        table.put("101201", 5.7);
        table.put("101210", 5.7);
        table.put("101211", 5.2);
        table.put("101220", 5.2);
        table.put("101221", 2.5);
        table.put("102001", 8.3);
        table.put("102011", 7.0);
        table.put("102021", 5.4);
        table.put("102101", 6.5);
        table.put("102111", 5.8);
        table.put("102121", 2.6);
        table.put("102201", 5.3);
        table.put("102211", 2.1);
        table.put("102221", 1.3);
        table.put("110000", 9.5);
        table.put("110001", 9.0);
        table.put("110010", 8.8);
        table.put("110011", 7.6);
        table.put("110020", 7.6);
        table.put("110021", 7.0);
        table.put("110100", 9.0);
        table.put("110101", 7.7);
        table.put("110110", 7.5);
        table.put("110111", 6.2);
        table.put("110120", 6.1);
        table.put("110121", 5.3);
        table.put("110200", 7.7);
        table.put("110201", 6.6);
        table.put("110210", 6.8);
        table.put("110211", 5.9);
        table.put("110220", 5.2);
        table.put("110221", 3.0);
        table.put("111000", 8.9);
        table.put("111001", 7.8);
        table.put("111010", 7.6);
        table.put("111011", 6.7);
        table.put("111020", 6.2);
        table.put("111021", 5.8);
        table.put("111100", 7.4);
        table.put("111101", 5.9);
        table.put("111110", 5.7);
        table.put("111111", 5.7);
        table.put("111120", 4.7);
        table.put("111121", 2.3);
        table.put("111200", 6.1);
        table.put("111201", 5.2);
        table.put("111210", 5.7);
        table.put("111211", 2.9);
        table.put("111220", 2.4);
        table.put("111221", 1.6);
        table.put("112001", 7.1);
        table.put("112011", 5.9);
        table.put("112021", 3.0);
        table.put("112101", 5.8);
        table.put("112111", 2.6);
        table.put("112121", 1.5);
        table.put("112201", 2.3);
        table.put("112211", 1.3);
        table.put("112221", 0.6);
        table.put("200000", 9.3);
        table.put("200001", 8.7);
        table.put("200010", 8.6);
        table.put("200011", 7.2);
        table.put("200020", 7.5);
        table.put("200021", 5.8);
        table.put("200100", 8.6);
        table.put("200101", 7.4);
        table.put("200110", 7.4);
        table.put("200111", 6.1);
        table.put("200120", 5.6);
        table.put("200121", 3.4);
        table.put("200200", 7.0);
        table.put("200201", 5.4);
        table.put("200210", 5.2);
        table.put("200211", 4.0);
        table.put("200220", 4.0);
        table.put("200221", 2.2);
        table.put("201000", 8.5);
        table.put("201001", 7.5);
        table.put("201010", 7.4);
        table.put("201011", 5.5);
        table.put("201020", 6.2);
        table.put("201021", 5.1);
        table.put("201100", 7.2);
        table.put("201101", 5.7);
        table.put("201110", 5.5);
        table.put("201111", 4.1);
        table.put("201120", 4.6);
        table.put("201121", 1.9);
        table.put("201200", 5.3);
        table.put("201201", 3.6);
        table.put("201210", 3.4);
        table.put("201211", 1.9);
        table.put("201220", 1.9);
        table.put("201221", 0.8);
        table.put("202001", 6.4);
        table.put("202011", 5.1);
        table.put("202021", 2.0);
        table.put("202101", 4.7);
        table.put("202111", 2.1);
        table.put("202121", 1.1);
        table.put("202201", 2.4);
        table.put("202211", 0.9);
        table.put("202221", 0.4);
        table.put("210000", 8.8);
        table.put("210001", 7.5);
        table.put("210010", 7.3);
        table.put("210011", 5.3);
        table.put("210020", 6.0);
        table.put("210021", 5.0);
        table.put("210100", 7.3);
        table.put("210101", 5.5);
        table.put("210110", 5.9);
        table.put("210111", 4.0);
        table.put("210120", 4.1);
        table.put("210121", 2.0);
        table.put("210200", 5.4);
        table.put("210201", 4.3);
        table.put("210210", 4.5);
        table.put("210211", 2.2);
        table.put("210220", 2.0);
        table.put("210221", 1.1);
        table.put("211000", 7.5);
        table.put("211001", 5.5);
        table.put("211010", 5.8);
        table.put("211011", 4.5);
        table.put("211020", 4.0);
        table.put("211021", 2.1);
        table.put("211100", 6.1);
        table.put("211101", 5.1);
        table.put("211110", 4.8);
        table.put("211111", 1.8);
        table.put("211120", 2.0);
        table.put("211121", 0.9);
        table.put("211200", 4.6);
        table.put("211201", 1.8);
        table.put("211210", 1.7);
        table.put("211211", 0.7);
        table.put("211220", 0.8);
        table.put("211221", 0.2);
        table.put("212001", 5.3);
        table.put("212011", 2.4);
        table.put("212021", 1.4);
        table.put("212101", 2.4);
        table.put("212111", 1.2);
        table.put("212121", 0.5);
        table.put("212201", 1.0);
        table.put("212211", 0.3);
        table.put("212221", 0.1);

        LOOKUP_TABLE = Collections.unmodifiableMap(table);
    }

    static double lookupScore(String macroVector) {
        Double score = LOOKUP_TABLE.get(macroVector);
        if (score == null) {
            throw new IllegalArgumentException("Invalid MacroVector: " + macroVector);
        }
        return score;
    }

    static boolean contains(String macroVector) {
        return LOOKUP_TABLE.containsKey(macroVector);
    }

    private CvssV4Lookup() {
    }
}
