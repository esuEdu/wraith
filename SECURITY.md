# Security policy

wraith holds a CA key that can impersonate any site to the devices that trust it, and it
sees captured traffic in clear text. Security reports are taken seriously.

## Reporting a vulnerability

Report privately through GitHub:
[Security > Report a vulnerability](https://github.com/esuEdu/wraith/security/advisories/new).
Do not open a public issue.

Please include the wraith version, macOS version, and steps to reproduce.

| Step | Target |
| --- | --- |
| Acknowledge the report | 3 days |
| Confirm or reject it | 7 days |
| Fix released, for a CA key leak or the listener reachable from another host | 14 days |
| Fix released, for anything else | Next minor release |

Fixes ship as a patch release with a GitHub security advisory. Reporters are credited
unless they ask not to be.

## Supported versions

Only the latest minor release gets security fixes. Before v1.0.0, that is the latest `v0.x`.

## Scope

In scope: the `wraith` binary, its release workflow, and the Homebrew formula in
`esuEdu/homebrew-tap`.

Out of scope: an attacker who already runs code as your user (they can read
`~/.wraith/ca/ca.key` anyway), and apps that ignore the system proxy.
