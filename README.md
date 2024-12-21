# CryptographicArchiver

### Elegant encryption for your Swift data archives

A lightweight, easy-to-use Swift package that combines the power of Apple's CryptoKit and AppleArchive frameworks to provide seamless encryption and compression of data objects to a encrypted `.aea` file.

## Why CryptographicArchiver?

Have you ever needed to securely store large sensitive data that surpasses the keychain's capacity, while still leveraging the convenience of Apple's security framework? You can achieve this by storing your encryption key in the Keychain and using the CryptographicArchiver for your data, adding multiple layers of security. With CryptographicArchiveProcessor, it's as simple as:

```swift
// Encrypt your data
try await processor.encryptObject(mySecretData, withKey: key, destinationFilePath: "encrypted.aea")

// Decrypt when needed
let decrypted: MyType = try await processor.decryptObject(from: "encrypted.aea", withKey: key)
```

## Features

- ✨ Clean, modern async/await API
- 🔒 Built on Apple's secure CryptoKit framework
- 📦 Integrated compression using AppleArchive
- 💪 Type-safe encryption and decryption
- 🚀 Optimized for both small and large data sets
- 📱 iOS, macOS support

## Installation

Add this package to your project through Swift Package Manager:

```swift
dependencies: [
.package(url: "https://github.com/yourusername/CryptographicArchiver.git", from: "1.0.0")
]
```

## Quick Start

1. Make your data type conform to `CryptographicArchivable`:

```swift
struct SecretMessage: CryptographicArchivable {
    let message: String

    var data: Data? {
        message.data(using: .utf8)
    }

    init?(data: Data) {
        guard let message = String(data: data, encoding: .utf8) else { return nil }
        self.message = message
    }
}
```

2. Create a processor and encrypt your data:

```swift
let processor = CryptographicArchiveProcessor()
let key = SymmetricKey(size: .bits256)
let secretMessage = SecretMessage(message: "Top secret! 🤫")

try await processor.encryptObject(
    secretMessage,
    withKey: key,
    destinationFilePath: "secret.aea"
)

```

3. Decrypt when needed:

```swift
let decrypted: SecretMessage = try await processor.decryptObject(
    from: "secret.aea",
    withKey: key
)
print(decrypted.message) // "Top secret! 🤫"
```

## Advanced Usage

### Custom Configuration

```swift
let config = ProcessorConfiguration(
filePermissions: FilePermissions(rawValue: 0o600),
maxInMemoryFileSize: 5_000_000,
cpuThreshold: 50_000_000
)
let processor = CryptographicArchiveProcessor(configuration: config)
```

### Using Archive Encryption Context

```swift
let context = ArchiveEncryptionContext(
profile: .hkdf_sha256_aesctr_hmacecdhe_p256ecdsa_p256,
compressionAlgorithm: .lz4
)
let contextKey = try context.generateSymmetricKey()
try await processor.encryptObject(
secretData,
withKey: contextKey,
destinationFilePath: "encrypted.aea"
)
```

## Under the Hood

- **CryptoKit**: For secure encryption operations
- **AppleArchive**: For efficient compression and archiving
- **System**: For low-level file operations

This combination provides a robust foundation for secure data storage while maintaining excellent performance.

## Future Features

- [ ] Support for streaming large files
- [ ] Additional compression algorithms
- [ ] Key derivation helpers
- [ ] Encryption progress monitoring
- [ ] Multiple file archiving
- [ ] Custom encryption profiles
- [ ] Integration with Keychain

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

CryptographicArchiveProcessor is available under the MIT license. See the LICENSE file for more info.

---

Built with ❤️ using Swift and Apple's security frameworks
