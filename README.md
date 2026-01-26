# Authority Realization Engine (ARE)

Compiles human authority into executable, verifiable, and enforceable machine constraints.

## Overview

ARE is a governance compiler that transforms authority statements (legal, regulatory, organizational, contractual, or sovereign) into deterministic, executable artifacts. It operates above application code to bind systems to provable legitimacy.

ARE does not interpret authority at runtime; it realizes authority at compile time. This ensures no silent escalation, no implicit delegation, and no post-hoc reinterpretation.

## Architecture

<pre>
+-------------------+     +-------------------------+
|  Authority Input  |---->|   Authority Ingestion   |
+-------------------+     +------------+------------+
                                       |
                                       v
                         +-------------+--------------+
                         |     Normalization (AIR)    |
                         +-------------+--------------+
                                       |
                                       v
                         +-------------+--------------+
                         |   Validation & Resolution  |
                         +-------------+--------------+
                                       |
                                       v
                         +---------------+------------+
                         |  Compilation  |   Binding  |
                         +---------------+------------+
                                       |
                                       v
                         +-------------+-------------+
                         |    Runtime Enforcement    |
                         +---------------------------+
</pre>

## Components

### Authority Source and Scope  
Origin of legitimacy (law, contract, policy) paired with jurisdictional, temporal, and operational boundaries that constrain where and when authority applies.

### Authority Claims  
Permissions, prohibitions, obligations, and delegations. These four claim types are mutually exclusive semantic operators. Permissions grant ability subject to higher-precedence prohibitions. Prohibitions deny regardless of permissions unless explicitly overridden by higher authority. Obligations require action within scope; failure to act is a violation. Delegations transfer authority to issue claims only, never authority to act directly.

### Authority Graph  
Formal structure encoding precedence, inheritance, and delegation. Delegation chains must be finite, acyclic, and preserve monotonic scope reduction. Precedence resolves by source type (sovereign > legal > regulatory > organizational > contractual), then version/timestamp, then delegation depth, then scope specificity. Unresolvable conflicts fail closed.

### Authority Artifact  
Executable enforcement artifacts compiled from the validated authority graph. Compilation produces either a success (artifact + proof) or a closed failure with stage, violated invariant, and involved claim IDs.

### Authority Proof  
Machine-verifiable explanations of outcomes. Every enforcement decision traces back to its originating authority through a deterministic proof chain.

## Build

```bash
go build
```

## Test

```bash
go get -t are/tests

go test ./tests/... -v
```

## Run

```bash
./are # Linux/macOS

.\are.exe # Windows
```

## Design Principles

1. **Deterministic** - All stages are deterministic and replayable.
2. **Fail-Closed** - No implicit delegation or escalation. Ambiguous authority fails compilation.
3. **Explainable** - Every outcome has a verifiable authority proof.
4. **Modular** - Each stage is composable and testable independently.
5. **Compile-Time Realization** - Authority is resolved before execution, not interpreted at runtime.

## Requirements

- Go 1.21+