# Guided examples

This guide introduces authorization analysis without assuming a background in
formal logic. Every example uses an expression directly on the command line,
so there are no policy files to inspect first.

Run the commands from the repository root after installing the package. A
query that finds a violation or policy difference exits with status `1`. That
is useful in CI and does not mean the command failed.

## Boolean policies in two minutes

An **atom** is a fact that can be either true or false:

- `ADMIN`: the caller is an administrator.
- `PII_READ`: the caller has permission to read PII.
- `ACCOUNT_SUSPENDED`: the account is suspended.

Expressions combine those facts:

| Expression | Plain meaning |
|---|---|
| `A & B` | Both A and B must be true. |
| `A \| B` | Either A or B may be true. |
| `!A` | A must be false. |
| `A -> B` | Whenever A is true, B must also be true. |
| `(A \| B) & C` | Parentheses group conditions. |

For example:

```text
ADMIN | (EMPLOYEE & PII_READ)
```

means:

> Access is allowed to an administrator, or to an employee who has permission
> to read PII.

The analyzer works with four related concepts:

- An **access expression** says when access is granted.
- A **requirement** says what must be true whenever access is granted.
- An **assumption** records a fact or relationship guaranteed by the system.
- A **counterexample** is one concrete situation that violates a requirement.

An **explanation** is a smallest set of facts sufficient for a result. A fact
missing from an explanation is a _don't-care_: it can be either true or false.
That differs from an explicit negative such as `!ACCOUNT_SUSPENDED`, which
means the fact must be false.

## 1. Find a requirement bypass

Consider access to a user's Social Security number. Access is granted to:

1. An administrator.
2. An employee with PII-read permission.
3. A support operator using an override during an open incident.

```text
ADMIN | (EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)
```

The security requirement says every caller with access must have PII-read
permission or be an administrator:

```text
ADMIN | PII_READ
```

Verify the access rule against that requirement:

```console
authz verify \
  --access-expr 'ADMIN | (EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)' \
  --required-expr 'ADMIN | PII_READ' \
  --assume 'ADMIN -> EMPLOYEE'
```

The result includes:

```text
VIOLATED: access 'ADMIN | (EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)' does not imply requirement 'ADMIN | PII_READ'
counterexample: ADMIN=false, EMPLOYEE=false, PII_READ=false, SUPPORT_OVERRIDE=true, INCIDENT_OPEN=true
one subset-minimal explanation: !ADMIN & !PII_READ & SUPPORT_OVERRIDE & INCIDENT_OPEN
```

This identifies a modeled bypass: a non-administrator without PII-read
permission can use the support override during an incident. The negative facts
are necessary. Omitting `!PII_READ`, for example, would no longer explain why
the requirement is violated.

A policy owner could require `PII_READ` on the override path, or change the
requirement if emergency access is intentionally exempt. The analyzer shows
the conflict; it cannot decide which behavior the organization intends.

## 2. See every minimal access path

Verification returns one bypass explanation. The `explain` command enumerates
all minimal ways the access expression itself can hold:

```console
authz explain \
  --expr 'ADMIN | (EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)' \
  --assume 'ADMIN -> EMPLOYEE'
```

```text
EXPLANATIONS: 'ADMIN | (EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)'
active assumptions: 1
1: ADMIN
2: EMPLOYEE & PII_READ
3: SUPPORT_OVERRIDE & INCIDENT_OPEN
```

These are the three distinct access paths. `EMPLOYEE` does not appear beside
`ADMIN`, even though administrators are assumed to be employees. Once `ADMIN`
is true, `EMPLOYEE` adds no information needed to grant access.

Facts absent from a path are don't-cares. In the first explanation, for
example, `PII_READ`, `SUPPORT_OVERRIDE`, and `INCIDENT_OPEN` may each be either
true or false; `ADMIN` alone is sufficient.

## 3. Understand assumptions and implication

An implication such as:

```text
ADMIN -> EMPLOYEE
```

means:

> Whenever `ADMIN` is true, `EMPLOYEE` must also be true.

It does not mean every employee is an administrator, and it does not itself
grant access. When `ADMIN` is false, the implication places no restriction on
`EMPLOYEE`.

The effect is easier to see with a small query:

```console
authz explain \
  --expr 'PII_READ' \
  --assume 'ADMIN -> EMPLOYEE' \
  --assume 'EMPLOYEE -> PII_READ'
```

```text
EXPLANATIONS: 'PII_READ'
active assumptions: 2
1: ADMIN
2: EMPLOYEE
3: PII_READ
```

`ADMIN` is sufficient because the two guaranteed relationships lead from
administrator to employee to PII-read permission. `EMPLOYEE` is sufficient
for the same reason. The assumption formulas remain background context rather
than being copied into every explanation.

### Assumptions are a trust boundary

Use an assumption only for a relationship the system actually enforces. If a
relationship is merely desired, make it a requirement and verify it instead.
An incorrect assumption can hide exactly the problem you want to find.

For example, adding this assumption makes the earlier PII verification hold:

```console
authz verify \
  --access-expr 'ADMIN | (EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)' \
  --required-expr 'ADMIN | PII_READ' \
  --assume 'ADMIN -> EMPLOYEE' \
  --assume 'SUPPORT_OVERRIDE -> PII_READ'
```

```text
HOLDS: access 'ADMIN | (EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)' implies requirement 'ADMIN | PII_READ'
```

That result is useful only if the application guarantees that every support
override carries PII-read permission. Adding the assumption merely to silence
the violation would make the model misleading.

### Analyze a known value

An assumption can also constrain an atom to a known value:

```console
authz explain \
  --expr 'ADMIN | SUPPORT_OVERRIDE' \
  --assume '!ADMIN'
```

This asks: “How can access occur when the caller is known not to be an
administrator?” The only explanation is `SUPPORT_OVERRIDE`. A positive known
value uses `--assume 'ADMIN'`.

## 4. Review a policy change

Suppose the old policy allows employees with PII-read permission:

```text
EMPLOYEE & PII_READ
```

The new policy adds emergency support access:

```text
(EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)
```

Compare them directly:

```console
authz diff \
  --old-expr 'EMPLOYEE & PII_READ' \
  --new-expr '(EMPLOYEE & PII_READ) | (SUPPORT_OVERRIDE & INCIDENT_OPEN)'
```

```text
WIDENED
added-access example: EMPLOYEE=false, PII_READ=false, SUPPORT_OVERRIDE=true, INCIDENT_OPEN=true
one subset-minimal added-access explanation: !EMPLOYEE & SUPPORT_OVERRIDE & INCIDENT_OPEN
```

`WIDENED` means at least one situation is allowed by the new policy and denied
by the old one. It does not automatically mean the change is unsafe. The
counterexample and explanation show reviewers what changed so they can decide.

Diff output contains one explanation for each changed region and does not claim
that the explanation is unique.

## 5. Reduce a convoluted expression

This deliberately noisy policy contains redundant branches, conditions that
are always true, and conditions that can never be true:

```console
authz explain \
  --expr='(
    (ADMIN & MFA_REQUIRED)
    | (ADMIN & MFA_REQUIRED & DEVICE_TRUSTED)
    | (ADMIN & MFA_REQUIRED & (REGION_US | !REGION_US))
    | (EMPLOYEE & PII_READ & (ON_VPN | !ON_VPN))
    | (BREAK_GLASS & INCIDENT_OPEN & !ACCOUNT_SUSPENDED)
    | (CONTRACTOR & false)
    | (TEMP_ACCESS & !TEMP_ACCESS)
  )' \
  --assume='ADMIN -> MFA_REQUIRED' \
  --assume='BREAK_GLASS -> INCIDENT_OPEN'
```

The minimal explanations are:

```text
1: ADMIN
2: BREAK_GLASS & !ACCOUNT_SUSPENDED
3: EMPLOYEE & PII_READ
```

Whole sections disappear for specific reasons:

- `ADMIN -> MFA_REQUIRED` makes `MFA_REQUIRED` unnecessary beside `ADMIN`.
- The stricter `DEVICE_TRUSTED` branch adds nothing to the existing admin path.
- `REGION_US | !REGION_US` is always true, so region is irrelevant.
- `ON_VPN | !ON_VPN` is always true, so VPN status is irrelevant.
- `BREAK_GLASS -> INCIDENT_OPEN` makes `INCIDENT_OPEN` unnecessary beside
  `BREAK_GLASS`.
- `CONTRACTOR & false` can never grant access.
- `TEMP_ACCESS & !TEMP_ACCESS` is a contradiction and can never grant access.
- `!ACCOUNT_SUSPENDED` remains because that negative fact is necessary.

This is semantic reduction rather than text simplification: the analyzer shows
the smallest sufficient access paths without rewriting the original policy.

## What these results do not prove

The results are exact for the expressions and assumptions supplied to the
analyzer. They do not prove that those expressions match an application's code,
that atom values are computed correctly, or that the modeled behavior matches
business intent. Treat policy extraction, assumptions, and requirements as
part of the security review—not merely as input preparation.
