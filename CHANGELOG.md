# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2024-11-29
### Upgraded
- Keypop Calypso Crypto Legacy SAM API `0.6.0` -> `0.7.0`

## [0.8.0] - 2024-09-06
### Added
- Added an optimization to the SAM resource profile extension which consists in automatically adding the 
  **Get Challenge** command when selecting the SAM.
### Upgraded
- Keyple Service Resource Library `3.0.2` -> `3.1.0` (optimization of network exchanges)

## [0.7.1] - 2024-06-25
### Fixed
- Fixed the name of the field `stopOnUnsuccessfulStatusWord` in the adapter of `CardRequestSpi`. 
### Changed
- Logging improvement.
### Upgraded
- Keyple Service Resource Library `3.0.1` -> `3.0.2` (source code not impacted)

## [0.7.0] - 2024-04-17
### Upgraded
- Keypop Calypso Crypto Legacy SAM API `0.5.0` -> `0.6.0`

## [0.6.0] - 2024-04-12
### Changed
- Java source and target levels `1.6` -> `1.8`
### Upgraded
- Keypop Reader API `2.0.0` -> `2.0.1`
- Keypop Card API `2.0.0` -> `2.0.1`
- Keypop Calypso Card API `2.0.0` -> `2.1.0`
- Keypop Calypso Crypto Legacy SAM API `0.4.0` -> `0.5.0`
- Keypop Calypso Crypto Symmetric API `0.1.0` -> `0.1.1`
- Keyple Common API `2.0.0` -> `2.0.1`
- Keyple Util Lib `2.3.1` -> `2.4.0`
- Gradle `6.8.3` -> `7.6.4`

## [0.5.0] - 2024-01-10
### Upgraded
- Keypop Calypso Crypto Legacy SAM API `0.3.0` -> `0.4.0` (management of advanced SAM unlocking)

## [0.4.0] - 2023-11-28
:warning: Major version! Following the migration of the "Calypsonet Terminal" APIs to the
[Eclipse Keypop project](https://keypop.org), this library now implements Keypop interfaces.
### Added
- Added dependency to "Keypop Calypso Crypto Symmetric API" `0.1.0`
- Added S1D3 to S1D7 to the list of SAM types recognized by the library.
- Added a new interface `ContextSetting` to manage the limitations of some not fully compliant terminals.
- Added new methods to class `LegacySamExtensionService`:
  - `ContextSetting getContextSetting()` to access to the new interface.
  - `LegacySamApiFactory getLegacySamApiFactory()` to get an implementation of the `LegacySamApiFactory` Keypop interface.
  - `CardResourceProfileExtension createLegacySamResourceProfileExtension(LegacySamSelectionExtension legacySamSelectionExtension, String powerOnDataRegex)` 
- Added project status badges on `README.md` file.
### Changed
- Refactoring:
    - Class `LegacySamCardExtensionService` -> `LegacySamExtensionService`
### Removed
- Removed methods from class `LegacySamExtensionService`:
  - `LegacySamSelectionFactory getLegacySamSelectionFactory()` (now provided by the `LegacySamApiFactory` Keypop interface)
  - `LSSecuritySettingFactory getSecuritySettingFactory()` (now provided by the `LegacySamApiFactory` Keypop interface)
  - `LSTransactionManagerFactory getTransactionManagerFactory()` (now provided by the `LegacySamApiFactory` Keypop interface)
  - `LSCommandDataFactory getCommandDataFactory()` (now provided by the `LegacySamApiFactory` Keypop interface)
### Fixed
- CI: code coverage report when releasing.
### Upgraded
- Calypsonet Terminal Reader API `1.2.0` -> Keypop Reader API `2.0.0`
- Calypsonet Terminal Card API `1.0.0` -> Keypop Card API `2.0.0`
- Calypsonet Terminal Calypso API `1.8.0` -> Keypop Calypso Card API `2.0.0`
- Calypsonet Terminal Calypso Crypto Legacy SAM API `0.2.0` -> Keypop Calypso Crypto Legacy SAM API `0.3.0`
- Keyple Service Resource Library `2.0.2` -> `3.0.0`
- Keyple Util Library `2.3.0` -> `2.3.1` (source code not impacted)

## [0.3.0] - 2023-02-27
### Upgraded
- "Calypsonet Terminal Reader API" to version `1.2.0`.
- "Calypsonet Terminal Calypso Crypto Legacy SAM API" to version `0.2.0`.
- "Google Gson Library" (com.google.code.gson) to version `2.10.1`.
 
## [0.2.0] - 2022-12-13
### Added
- `LegacySamCardExtensionService` to gather all providers.

## [0.1.0] - 2022-12-12
This is the initial release.

[unreleased]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.9.0...HEAD
[0.9.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.8.0...0.9.0
[0.8.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.7.1...0.8.0
[0.7.1]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.7.0...0.7.1
[0.7.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-legacysam-java-lib/releases/tag/0.1.0