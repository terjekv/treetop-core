# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.0.6 - 2025-07-04

### Added

- Proper namespace support.
- Add `from_str` for `Action`, `Group`, and `User` to allow the creation from strings. For `Group` and `Action` the format is the canonical form, e.g. `<Namespaces::>Group::"group_name"` and `<Namespaces::>Action::"action_name"`, while for `User` you may also add unquoted groups bracketed by `[]` and seperated by comma (`,`) at the end, e.g. `User::"alice"[admins,users]`. For all input, quoting of the identity element is optional, so you may also use `User::alice`, `Group::admins`, or `DNS::Action::create_host`.

### Changed

- Updated Cedar to version [4.5](https://github.com/cedar-policy/cedar/releases/tag/v4.5.0). From a consumer perspective, the major change is support for [trailing commas](https://github.com/cedar-policy/rfcs/blob/main/text/0071-trailing-commas.md) in Cedar policies.

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
