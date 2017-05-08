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
 * Defines an interface for CVSS versions.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public interface Cvss {

    /**
     * Calculates a CVSS score.
     * @return a Score object
     * @since 1.0.0
     */
    Score calculateScore();

    /**
     * Returns the CVSS vector
     * @return a String of the CVSS vector
     * @since 1.0.0
     */
    String getVector();

}
