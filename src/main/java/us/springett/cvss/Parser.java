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

import java.util.function.Function;

interface Parser<T extends Cvss> {

    T parseVector(String vector);

    static <E extends Enum<?>> E requireNonNull(final String metric, final char value, final Function<Character, E> function) {
        final E result = function.apply(value);
        if (result == null) {
            throw new MalformedVectorException("Invalid value for metric " + metric + ": " + value);
        }
        return result;
    }

    static <E extends Enum<?>> E requireNonNull(final String metric, final String value, final Function<String, E> function) {
        final E result = function.apply(value);
        if (result == null) {
            throw new MalformedVectorException("Invalid value for metric " + metric + ": " + value);
        }
        return result;
    }
}
