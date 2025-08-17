# PasswordHasher Change Log

## Singulink.Cryptography.PasswordHasher

### V2.1

- Added .NET 8 target
- Updated dependencies

### V2.0

- Added Argon2 support via the **Singulink.Cryptography.PasswordHasher.Argon2** package
- Added hash encryption support
- Added password normalization support (enabled by default)

### V3.0

- Removed .NET Standard 2.1 target
- Added `IPasswordHasher` interface
- `PasswordHasher` constructors and `PasswordHasherOptions` have been modified to support more standardized options patterns

## Singulink.Cryptography.PasswordHasher.Argon2

### V2.0

- Added .NET 8 target
- Updated Isopoh.Cryptography.Argon2 to V2.0.0

### V3.0

- Removed .NET Standard 2.1 target
- Added static `Create()` method