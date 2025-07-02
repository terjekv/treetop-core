# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Proper namespace support.

## 0.0.5 - 2025-06-28

### Added

- Group support. Group principals are `Group::<Namespace::>"group_name"`, and you can use the `in` operator to match its group members. Note that using `==` will only match the group itself, not its members. Also see the readme for more details on how to use groups.

## 0.0.4 - 2025-06-27

### Changed

- `Decision::Allow` responses now include a `PermitPolicy`, which contains the policy that was matched, with two fields:
  - `literal`: The literal representation of the policy that was matched, in Cedar syntax.
  - `json`: The JSON representation of the policy that was matched.

## 0.0.3 - 2025-06-25

### Added

- Support for generic resources. Passing `Resource::Generic { kind: "House".into(), id: "house-1".into() }` to a request will match policies that use `resource is House` and its `id` property will be `"house-1"`. See the readme for more details on how to use generic resources.
