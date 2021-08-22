# Change Log

## [v1.9.0](https://github.com/johanbrandhorst/certify/tree/v1.9.0) (2021-08-22)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.8.1...v1.9.0)

**Implemented enhancements:**

- Release c3673d8 [\#127](https://github.com/johanbrandhorst/certify/issues/127)

**Fixed bugs:**

- improper use of singleflight [\#130](https://github.com/johanbrandhorst/certify/issues/130)

**Merged pull requests:**

- Update module github.com/ory/dockertest to v3.7.0 [\#139](https://github.com/johanbrandhorst/certify/pull/139) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Upgrade all dependencies [\#137](https://github.com/johanbrandhorst/certify/pull/137) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Configure Renovate [\#136](https://github.com/johanbrandhorst/certify/pull/136) ([renovate[bot]](https://github.com/apps/renovate))
- Upgrade vault version [\#135](https://github.com/johanbrandhorst/certify/pull/135) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Upgrade CFSSL version [\#134](https://github.com/johanbrandhorst/certify/pull/134) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Rewrite AWS issuer [\#133](https://github.com/johanbrandhorst/certify/pull/133) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Get request context from parameter in Go 1.17 [\#132](https://github.com/johanbrandhorst/certify/pull/132) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Use certificate name as singleflight key [\#131](https://github.com/johanbrandhorst/certify/pull/131) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.8.1](https://github.com/johanbrandhorst/certify/tree/v1.8.1) (2020-09-09)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.8.0...v1.8.1)

**Implemented enhancements:**

- Missing vault issuer documentation [\#121](https://github.com/johanbrandhorst/certify/issues/121)
- Migrate container tests to podrick [\#93](https://github.com/johanbrandhorst/certify/issues/93)

**Fixed bugs:**

- Generation CI job is failing [\#125](https://github.com/johanbrandhorst/certify/issues/125)
- Possible nil panic in Vault issuer [\#123](https://github.com/johanbrandhorst/certify/issues/123)
- go 1.15 x509 common name deprecation [\#122](https://github.com/johanbrandhorst/certify/issues/122)
- Vault api go module incorrect [\#116](https://github.com/johanbrandhorst/certify/issues/116)

**Merged pull requests:**

- Generate changelog for v1.8.1 [\#128](https://github.com/johanbrandhorst/certify/pull/128) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Remove moq generation step [\#126](https://github.com/johanbrandhorst/certify/pull/126) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Fix crash in Vault issuer [\#124](https://github.com/johanbrandhorst/certify/pull/124) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add golangpiter talk to README [\#120](https://github.com/johanbrandhorst/certify/pull/120) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Update dependency versions [\#119](https://github.com/johanbrandhorst/certify/pull/119) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.8.0](https://github.com/johanbrandhorst/certify/tree/v1.8.0) (2020-04-01)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.7.0...v1.8.0)

**Implemented enhancements:**

- Support alt\_names in Vault request [\#114](https://github.com/johanbrandhorst/certify/issues/114)

**Fixed bugs:**

- Undefined: acmpcaiface.ACMPCAAPI [\#111](https://github.com/johanbrandhorst/certify/issues/111)

**Merged pull requests:**

- Generate changelog for 1.8.0 [\#117](https://github.com/johanbrandhorst/certify/pull/117) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add SubjectAlternativeNames and IPSubjectAlternativeNames to Vault issuer [\#115](https://github.com/johanbrandhorst/certify/pull/115) ([nvx](https://github.com/nvx))

## [v1.7.0](https://github.com/johanbrandhorst/certify/tree/v1.7.0) (2020-02-28)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.7.0-alpha2...v1.7.0)

**Fixed bugs:**

- AWS CM failing [\#108](https://github.com/johanbrandhorst/certify/issues/108)

**Closed issues:**

- gRPC with Vault - why does server initiates a CSR with client CN? [\#107](https://github.com/johanbrandhorst/certify/issues/107)

**Merged pull requests:**

- Generate changelog for 1.7.0 [\#110](https://github.com/johanbrandhorst/certify/pull/110) ([johanbrandhorst](https://github.com/johanbrandhorst))
- issuers/aws: Fix incorrectly concatenated certificates [\#109](https://github.com/johanbrandhorst/certify/pull/109) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.7.0-alpha2](https://github.com/johanbrandhorst/certify/tree/v1.7.0-alpha2) (2019-12-29)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.7.0-alpha...v1.7.0-alpha2)

**Implemented enhancements:**

- Rotating Vault tokens. [\#101](https://github.com/johanbrandhorst/certify/issues/101)

**Merged pull requests:**

- Add Vault AuthMethod to sidecar [\#105](https://github.com/johanbrandhorst/certify/pull/105) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.7.0-alpha](https://github.com/johanbrandhorst/certify/tree/v1.7.0-alpha) (2019-12-26)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.6.0...v1.7.0-alpha)

**Implemented enhancements:**

- Ability to reuse private key [\#99](https://github.com/johanbrandhorst/certify/issues/99)
- Update CFSSL to 1.4.0 [\#94](https://github.com/johanbrandhorst/certify/issues/94)
- Publish docker container for certify proxy [\#90](https://github.com/johanbrandhorst/certify/issues/90)

**Merged pull requests:**

- Add renewable token auth method to Vault issuer [\#104](https://github.com/johanbrandhorst/certify/pull/104) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add AuthMethod to Vault issuer [\#103](https://github.com/johanbrandhorst/certify/pull/103) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Reuse keys by default [\#100](https://github.com/johanbrandhorst/certify/pull/100) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add logger to CFSSL tests [\#98](https://github.com/johanbrandhorst/certify/pull/98) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Use podrick master instead of branch [\#97](https://github.com/johanbrandhorst/certify/pull/97) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Migrate CFSSL tests to podrick [\#96](https://github.com/johanbrandhorst/certify/pull/96) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Update cfssl [\#95](https://github.com/johanbrandhorst/certify/pull/95) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Speed up fetching by removing branches [\#92](https://github.com/johanbrandhorst/certify/pull/92) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Remove time param from presentation link [\#87](https://github.com/johanbrandhorst/certify/pull/87) ([jjshanks](https://github.com/jjshanks))

## [v1.6.0](https://github.com/johanbrandhorst/certify/tree/v1.6.0) (2019-10-03)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.5.1...v1.6.0)

**Merged pull requests:**

- Update changelog for v1.6.0 [\#86](https://github.com/johanbrandhorst/certify/pull/86) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Support setting URI SANs in CSRs [\#85](https://github.com/johanbrandhorst/certify/pull/85) ([eandre](https://github.com/eandre))

## [v1.5.1](https://github.com/johanbrandhorst/certify/tree/v1.5.1) (2019-09-26)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.5.0...v1.5.1)

**Fixed bugs:**

- Certify fills debug log output with `getting certificate` logs [\#82](https://github.com/johanbrandhorst/certify/issues/82)

**Merged pull requests:**

- Update changelog for v1.5.1 [\#84](https://github.com/johanbrandhorst/certify/pull/84) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Remove excessive logging [\#83](https://github.com/johanbrandhorst/certify/pull/83) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.5.0](https://github.com/johanbrandhorst/certify/tree/v1.5.0) (2019-09-17)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.4.0...v1.5.0)

**Merged pull requests:**

- Update changelog for v1.5.0 [\#80](https://github.com/johanbrandhorst/certify/pull/80) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add sidecar container [\#79](https://github.com/johanbrandhorst/certify/pull/79) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.4.0](https://github.com/johanbrandhorst/certify/tree/v1.4.0) (2019-07-09)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.3.0...v1.4.0)

**Implemented enhancements:**

- Add better tests for OtherSans setting [\#71](https://github.com/johanbrandhorst/certify/issues/71)
- Try to generate moq in module mode again [\#51](https://github.com/johanbrandhorst/certify/issues/51)
- Allow a logger to be configured [\#36](https://github.com/johanbrandhorst/certify/issues/36)

**Merged pull requests:**

- main: Update changelog for v1.4.0 [\#76](https://github.com/johanbrandhorst/certify/pull/76) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add configurable logger [\#75](https://github.com/johanbrandhorst/certify/pull/75) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add noopCache to simplify some logic [\#74](https://github.com/johanbrandhorst/certify/pull/74) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Properly validate OtherSANs [\#73](https://github.com/johanbrandhorst/certify/pull/73) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.3.0](https://github.com/johanbrandhorst/certify/tree/v1.3.0) (2019-06-18)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.2.0...v1.3.0)

**Implemented enhancements:**

- Implement an issuer for whatever Istio uses under the hood to issue certs [\#39](https://github.com/johanbrandhorst/certify/issues/39)

**Merged pull requests:**

- main: update changelog for v1.3.0 [\#72](https://github.com/johanbrandhorst/certify/pull/72) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add support for URI sans [\#70](https://github.com/johanbrandhorst/certify/pull/70) ([nvx](https://github.com/nvx))

## [v1.2.0](https://github.com/johanbrandhorst/certify/tree/v1.2.0) (2019-04-12)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.1.5...v1.2.0)

**Implemented enhancements:**

- Create submodules for issuers [\#67](https://github.com/johanbrandhorst/certify/issues/67)

**Merged pull requests:**

- main: update changelog for v1.2.0 [\#69](https://github.com/johanbrandhorst/certify/pull/69) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Clean up go modules. [\#68](https://github.com/johanbrandhorst/certify/pull/68) ([SpeedyCoder](https://github.com/SpeedyCoder))
- Add a Gitter chat badge to README.md [\#66](https://github.com/johanbrandhorst/certify/pull/66) ([gitter-badger](https://github.com/gitter-badger))

## [v1.1.5](https://github.com/johanbrandhorst/certify/tree/v1.1.5) (2019-04-05)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.1.4...v1.1.5)

**Merged pull requests:**

- main: update changelog for v1.1.5 [\#65](https://github.com/johanbrandhorst/certify/pull/65) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Fixes missing Leaf in cert [\#64](https://github.com/johanbrandhorst/certify/pull/64) ([jlindsey](https://github.com/jlindsey))
- main: update changelog for v1.1.4 [\#62](https://github.com/johanbrandhorst/certify/pull/62) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.1.4](https://github.com/johanbrandhorst/certify/tree/v1.1.4) (2019-03-06)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.1.3...v1.1.4)

**Merged pull requests:**

- Remove golangci-lint job [\#61](https://github.com/johanbrandhorst/certify/pull/61) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Update golangci-lint version [\#60](https://github.com/johanbrandhorst/certify/pull/60) ([johanbrandhorst](https://github.com/johanbrandhorst))
- switch dir cache away from gob to marshalling pem-encoded certs and keys [\#59](https://github.com/johanbrandhorst/certify/pull/59) ([jlindsey](https://github.com/jlindsey))
- add Users section to README [\#57](https://github.com/johanbrandhorst/certify/pull/57) ([johanbrandhorst](https://github.com/johanbrandhorst))
- adds public key types to Gob registry [\#56](https://github.com/johanbrandhorst/certify/pull/56) ([jlindsey](https://github.com/jlindsey))
- Nicer badges! [\#55](https://github.com/johanbrandhorst/certify/pull/55) ([johanbrandhorst](https://github.com/johanbrandhorst))
- main: update changelog for v1.1.3 [\#53](https://github.com/johanbrandhorst/certify/pull/53) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.1.3](https://github.com/johanbrandhorst/certify/tree/v1.1.3) (2019-03-01)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.1.2...v1.1.3)

**Merged pull requests:**

- Fixes Dir cache gob encoding, with tests [\#52](https://github.com/johanbrandhorst/certify/pull/52) ([jlindsey](https://github.com/jlindsey))

## [v1.1.2](https://github.com/johanbrandhorst/certify/tree/v1.1.2) (2019-02-23)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.1.1...v1.1.2)

**Fixed bugs:**

- Using dep with certify adds a lot of additional dependencies [\#48](https://github.com/johanbrandhorst/certify/issues/48)

**Merged pull requests:**

- main: update changelog for v1.1.2 [\#50](https://github.com/johanbrandhorst/certify/pull/50) ([johanbrandhorst](https://github.com/johanbrandhorst))
- main: move tools file into subfolder [\#49](https://github.com/johanbrandhorst/certify/pull/49) ([johanbrandhorst](https://github.com/johanbrandhorst))
- main: update changelog for v1.1.1 [\#47](https://github.com/johanbrandhorst/certify/pull/47) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.1.1](https://github.com/johanbrandhorst/certify/tree/v1.1.1) (2019-02-19)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.1.0...v1.1.1)

**Merged pull requests:**

- all: remove vendor folder [\#46](https://github.com/johanbrandhorst/certify/pull/46) ([johanbrandhorst](https://github.com/johanbrandhorst))
- issuers/vault: simplify alternative mount point tests [\#44](https://github.com/johanbrandhorst/certify/pull/44) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add section on how it works to README [\#43](https://github.com/johanbrandhorst/certify/pull/43) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add issue templates [\#42](https://github.com/johanbrandhorst/certify/pull/42) ([johanbrandhorst](https://github.com/johanbrandhorst))
- main: update changelog for v1.1.0 [\#41](https://github.com/johanbrandhorst/certify/pull/41) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.1.0](https://github.com/johanbrandhorst/certify/tree/v1.1.0) (2019-02-16)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v1.0.0...v1.1.0)

**Merged pull requests:**

- adds ability to configure mount point name for vault pki [\#40](https://github.com/johanbrandhorst/certify/pull/40) ([jlindsey](https://github.com/jlindsey))
- Add logo [\#35](https://github.com/johanbrandhorst/certify/pull/35) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v1.0.0](https://github.com/johanbrandhorst/certify/tree/v1.0.0) (2019-02-03)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v0.3.0...v1.0.0)

**Closed issues:**

- Migrate CI to CircleCI for better Github integration and required checks [\#29](https://github.com/johanbrandhorst/certify/issues/29)
- Allow certificate key type to be configured [\#27](https://github.com/johanbrandhorst/certify/issues/27)
- Re-enable generate CI check [\#26](https://github.com/johanbrandhorst/certify/issues/26)
- Migrate to Go modules [\#24](https://github.com/johanbrandhorst/certify/issues/24)

**Merged pull requests:**

- main: Add CHANGELOG.md [\#34](https://github.com/johanbrandhorst/certify/pull/34) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Allow key configuration [\#33](https://github.com/johanbrandhorst/certify/pull/33) ([johanbrandhorst](https://github.com/johanbrandhorst))
- main: update README.md with CircleCI badge [\#31](https://github.com/johanbrandhorst/certify/pull/31) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Migrate CI to CircleCI [\#30](https://github.com/johanbrandhorst/certify/pull/30) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Unexport Connect, add CFFSL test for unencrypted connections [\#28](https://github.com/johanbrandhorst/certify/pull/28) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Migrate from dep to go modules [\#25](https://github.com/johanbrandhorst/certify/pull/25) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v0.3.0](https://github.com/johanbrandhorst/certify/tree/v0.3.0) (2019-01-26)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v0.2.0...v0.3.0)

**Closed issues:**

- Add support for AWS CA [\#16](https://github.com/johanbrandhorst/certify/issues/16)
- Make it possible to create issuers from Vault/CFSSL clients. [\#11](https://github.com/johanbrandhorst/certify/issues/11)

**Merged pull requests:**

- Minor fixes [\#23](https://github.com/johanbrandhorst/certify/pull/23) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add AWS CA issuer [\#22](https://github.com/johanbrandhorst/certify/pull/22) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Allow issuers to be created from API clients [\#21](https://github.com/johanbrandhorst/certify/pull/21) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v0.2.0](https://github.com/johanbrandhorst/certify/tree/v0.2.0) (2019-01-26)
[Full Changelog](https://github.com/johanbrandhorst/certify/compare/v0.1.0...v0.2.0)

**Closed issues:**

- Switch Vault Issuer to CSR signer [\#12](https://github.com/johanbrandhorst/certify/issues/12)

**Merged pull requests:**

- Deduplicate simultaneous issue requests, small improvements [\#20](https://github.com/johanbrandhorst/certify/pull/20) ([johanbrandhorst](https://github.com/johanbrandhorst))
- issuers/vault: Switch to CSR signing [\#19](https://github.com/johanbrandhorst/certify/pull/19) ([johanbrandhorst](https://github.com/johanbrandhorst))

## [v0.1.0](https://github.com/johanbrandhorst/certify/tree/v0.1.0) (2018-09-26)
**Closed issues:**

- Add better explanation to CFSSL struct components [\#14](https://github.com/johanbrandhorst/certify/issues/14)
- Implement Cloudflare CA issuer backend [\#5](https://github.com/johanbrandhorst/certify/issues/5)

**Merged pull requests:**

- vault: fix ca\_chain conversion [\#18](https://github.com/johanbrandhorst/certify/pull/18) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Whoops missing comma. [\#17](https://github.com/johanbrandhorst/certify/pull/17) ([bweston92](https://github.com/bweston92))
- Better cfssl docs [\#15](https://github.com/johanbrandhorst/certify/pull/15) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add cfssl issuer [\#13](https://github.com/johanbrandhorst/certify/pull/13) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Made the repo public, maybe now it'll work? [\#10](https://github.com/johanbrandhorst/certify/pull/10) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add directory Cache implementation [\#9](https://github.com/johanbrandhorst/certify/pull/9) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Remove pipeline status badge :\(. [\#8](https://github.com/johanbrandhorst/certify/pull/8) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add pipeline status badge [\#7](https://github.com/johanbrandhorst/certify/pull/7) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Update README.md [\#6](https://github.com/johanbrandhorst/certify/pull/6) ([lukasmalkmus](https://github.com/lukasmalkmus))
- Rename repo and package to Certify [\#4](https://github.com/johanbrandhorst/certify/pull/4) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Add initial CI configuration [\#3](https://github.com/johanbrandhorst/certify/pull/3) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Remove multiple urls [\#2](https://github.com/johanbrandhorst/certify/pull/2) ([johanbrandhorst](https://github.com/johanbrandhorst))
- Initial checkin [\#1](https://github.com/johanbrandhorst/certify/pull/1) ([johanbrandhorst](https://github.com/johanbrandhorst))



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*