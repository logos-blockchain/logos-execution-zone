# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support Pairing Mode for Keycard version 3.2

### Fixed

- Older versions not supported. Python 3.10+ now supported

## [0.3.0] - 2025-08-24

### Changed

- Open Secure Channel also mutually authenticates unless specified otherwise.
- SignatureResult object returned by sign methods
- Identity returns public key.

## [0.2.0] - 2025-08-06

### Added

- LOAD KEY command
- SET PINLESS PATH command
- GENERATE MNEMONIC command
- DERIVE KEY command

## [0.1.0] - 2025-08-05

### Added

- INIT command
- IDENT command
- OPEN SECURE CHANNEL command
- MUTUALLY AUTHENTICATE command
- PAIR command
- UNPAIR command
- GET STATUS command
- VERIFY PIN command
- CHANGE PIN command
- UNBLOCK PIN command
- REMOVE KEY command
- GENERATE KEY command
- SIGN command
- EXPORT KEY command
- GET_DATA command
- STORE DATA command
- FACTORY RESET command


[unreleased]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mmlado/keycard-py/releases/tag/v0.1.0