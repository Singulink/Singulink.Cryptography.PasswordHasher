# Singulink.Cryptography.PasswordHasher

[![Join the chat](https://badges.gitter.im/Singulink/community.svg)](https://gitter.im/Singulink/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![View nuget packages](https://img.shields.io/nuget/v/Singulink.Cryptography.PasswordHasher.svg)](https://www.nuget.org/packages/Singulink.Cryptography.PasswordHasher/)
[![Build and Test](https://github.com/Singulink/Singulink.Cryptography.PasswordHasher/workflows/build%20and%20test/badge.svg)](https://github.com/Singulink/Singulink.Cryptography.PasswordHasher/actions?query=workflow%3A%22build+and+test%22)

PasswordHasher greatly simplifies implementing security best practices with upgradable hash algorithm passwords. PasswordHasher algorithms are "upgradable" in the sense that the library facilitates upgrading password hashes to a different algorithm or increasing the number of iterations that are performed.

Out of the box, PasswordHasher supports SHA256, SHA384 and SHA512 using PBKDF2 for iteration (as well as SHA1, but only for upgrading legacy hashes). Any other algorithm (i.e. bcrypt, scrypt, etc) can be easily plugged into PasswordHasher by implementing the `PasswordHashAlgorithm` class, which only requires overriding a single `CreateHash` method.

PasswordHasher is part of the Singulink Libraries collection. Visit https://github.com/Singulink/ to see the full list of libraries available.

## Installation

The package is available on NuGet - simply install the `Singulink.Cryptography.PasswordHasher` package.

**Supported Runtimes**: Anywhere .NET Standard 2.1+ is supported, including:
- .NET Core 3.0+
- Mono 6.4+
- Xamarin.iOS 12.16+
- Xamarin.Android 10.0+

## Usage

To create a PasswordHasher you use the following constructor:

```c#
public PasswordHasher(PasswordHashAlgorithm algorithm, int iterations, params PasswordHashAlgorithm[] legacyAlgorithms)
```

The `algorithm` and `iterations` parameters specify what the "main" algorithm should be. The `legacyAlgorithms` parameter specifies any additional algorithms that the hasher should be capable of working with, i.e. any older hash algorithms that were substituted for the main algorithm but which the database may still utilize for hashes that have not been fully rehashed yet.

The `PasswordHasher` class contains the following primary methods:

```c#
string Hash(string password);
bool Verify(string hash, string password);
bool RequiresRehash(string hash);
bool RequiresHashChainUpgrade(string hash);
string? UpgradeHashChain(string hash);
```

The first two methods should be self-explanatory: `Hash` produces a password hash, where-as `Verify` is used to verify a hash/password combo.

The last three methods are where it gets interesting:
- `RequiresRehash`: Returns true if a hash should be regenerated from the known password to eliminate algorithm chaining or to produce a hash with the desired algorithm and iteration count.
- `RequiresHashChainUpgrade`: Returns true if the hash chain should be upgraded so that it utilizes the desired algorithm and number of iterations.
- `UpgradeHashChain`: Upgrades the specified hash to the main algorithm and required number of iterations without knowing the password via algorithm chaining. The resulting hash will return true if passed into the `RequiresRehash" method, which should be tested on successful user login if hash chains were upgraded at some point so that a new hash without chaining can replace the chained hash. This method returns null if the hash does not require an upgrade. Hashes that already use the main algorithm with a lower number of iterations will chain the difference needed to reach the required total iteration count.

The format of the hash string is as follows:

```
[hash algorithm]:[iterations]:[salt] [hash]
```

If the hash chain was upgraded at some point (i.e. had additional algorithms or iterations applied to it), then those are added to the list. For example, if we started with SHA256 with 1000 iterations and upgraded to SHA512 with 20,000 iterations, the hash string might look something like this:

```
"SHA256:1000:9QTkU8cSJ8xXkUdrx8qQVg== SHA512:20000:dlZfZk6CQstiyUAnZH5L7w== 07qYVKg1yx+AiRP+2oLxv3ozRmJ4tvb/IkgnsCO40LXT8Pm+bXXQnHoqKTQMy7e4IbMbTzOVH7cDqqBZ5RyygA=="
```

Usage of the library is best demonstrated with an example:

```c#
string mikePassword = "ABCDEFEG";
string rossPassword = "12345678";

// Create hasher that uses SHA256 with 10,000 PBKDF2 iterations

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 10000);

// Create password hashes for Mike and Ross

string mikeHash = hasher.Hash(mikePassword);
string rossHash = hasher.Hash(rossPassword);

// Verify Mike's password

bool success = hasher.Verify(mikeHash, mikePassword); // true

// Upgrade hashes to SHA256 with 20,000 iterations by running a script like this:

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 20000);

foreach (var user in GetUsers())
{
    if (hasher.RequiresHashChainUpgrade(user.PasswordHash))
        user.PasswordHash = hasher.UpgradeHashChain(user.PasswordHash);
}

// Hashes in the database are now composed of a 10,000 iteration SHA256 hash chained to 
// another 10,000 iteration SHA256 hash.
// Use login code as follows so that upgraded hash chains are rehashed to a normal unchained 
// hash on successful login:

bool Login(string username, string password)
{
    var user = GetUser(username);

    if (user == null || !hasher.Verify(user.PasswordHash, password))
        return false;

    // Generate a new 20,000 iteration unchained SHA256 hash if needed
    if (hasher.RequiresRehash(user.PasswordHash))
        user.PasswordHash = hasher.Hash(password);
}
```