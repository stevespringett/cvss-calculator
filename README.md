[![Build Status](https://travis-ci.org/stevespringett/cvss-calculator.svg?branch=master)](https://travis-ci.org/stevespringett/cvss-calculator)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/cb8fdf4b23df4ac993cadbbeb14c743c)](https://www.codacy.com/app/stevespringett/cvss-calculator?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=stevespringett/cvss-calculator&amp;utm_campaign=Badge_Grade)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)][Apache 2.0]

CVSS Calculator
=====================================

CVSS Calculator is a Java library for calculating CVSSv2 and CVSSv3 scores and vectors,
including support for base scores, impact scores, and exploitability scores.

Compiling
-------------------

> $ mvn clean package

Usage Example
-------------------
```java
// Performs a new calculation using CVSSv3
CvssV3 cvssV3 = new CvssV3()
    .attackVector(AttackVector.NETWORK)
    .attackComplexity(AttackComplexity.LOW)
    .privilegesRequired(PrivilegesRequired.HIGH)
    .userInteraction(UserInteraction.NONE)
    .scope(Scope.UNCHANGED)
    .confidentiality(CIA.HIGH)
    .integrity(CIA.HIGH)
    .availability(CIA.HIGH);

Score score = cvssV3.calculateScore();
```
```java
// Parses an existing CVSS v2 or v3 vector
Cvss cvss = Cvss.fromVector(vector);
Score score = cvss.calculateScore();
```

Maven Usage
-------------------
CVSS Calculator is available in the Maven Central Repository.

```xml
<dependency>
    <groupId>us.springett</groupId>
    <artifactId>cvss-calculator</artifactId>
    <version>1.2.0</version>
</dependency>
```

Copyright & License
-------------------

CVSS Calculator is Copyright (c) Steve Springett. All Rights Reserved.

All other trademarks are property of their respective owners.

Permission to modify and redistribute is granted under the terms of the [Apache 2.0] license.

  [Apache 2.0]: http://www.apache.org/licenses/LICENSE-2.0.txt
