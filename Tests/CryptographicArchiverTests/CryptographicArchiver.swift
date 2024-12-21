import AppleArchive
import CryptoKit
import Foundation
import System
import Testing

@testable import CryptographicArchiver

// Test Model
struct TestData: CryptographicArchivable {
    let message: String

    var data: Data? {
        message.data(using: .utf8)
    }

    init(message: String) {
        self.message = message
    }

    init?(data: Data) {
        guard let message = String(data: data, encoding: .utf8) else { return nil }
        self.message = message
    }
}

final class CryptographicArchiveProcessorTests {
    let tempDirectory = FileManager.default.temporaryDirectory

    private func uniqueFilePath(for testName: String) -> String {
        return tempDirectory.appendingPathComponent("\(testName).aea").path
    }

    // Helper to create a processor with default configuration
    private func createProcessor() -> CryptographicArchiveProcessor {
        return CryptographicArchiveProcessor()
    }

    // Helper to create a processor with custom configuration
    private func createProcessor(configuration: ProcessorConfiguration) -> CryptographicArchiveProcessor {
        return CryptographicArchiveProcessor(configuration: configuration)
    }

    // MARK: - Setup and Teardown

    func setUp() throws {
        // Clean up any existing test files
        try? FileManager.default.removeItem(at: tempDirectory)
    }

    func tearDown() throws {
        // Clean up test files after each test
        let fileManager = FileManager.default
        let contents = try? fileManager.contentsOfDirectory(
            at: tempDirectory,
            includingPropertiesForKeys: nil,
            options: []
        )

        // Remove all .aea files in the temporary directory
        try contents?.forEach { url in
            if url.pathExtension == "aea" {
                try fileManager.removeItem(at: url)
            }
        }
    }

    // MARK: - Tests

    @Test("Test successful encryption and decryption")
    func testEncryptionAndDecryption() async throws {
        // Arrange
        let processor = createProcessor()
        let testKey = SymmetricKey(size: .bits256)
        let originalMessage = "L1FPnexFbjkTBgHQJd6xfpHt9ijLivitf473hyStusffxQJu32xv"
        let testData = TestData(message: originalMessage)
        let encryptedPath = uniqueFilePath(for: "testEncryptionAndDecryption")

        // Act
        try await processor.encryptObject(testData, withKey: testKey, destinationFilePath: encryptedPath)

        let decryptedData: TestData = try await processor.decryptObject(
            from: encryptedPath,
            withKey: testKey
        )

        // Assert
        #expect(decryptedData.message == originalMessage)
        #expect(FileManager.default.fileExists(atPath: encryptedPath))
    }

    @Test("Test encryption with empty data")
    func testEncryptionWithEmptyData() async throws {
        // Arrange
        let processor = createProcessor()
        let testKey = SymmetricKey(size: .bits256)
        let emptyData = TestData(message: "")
        let encryptedPath = uniqueFilePath(for: "testEncryptionWithEmptyData")

        // Act & Assert
        await #expect(throws: CryptographicProcessorError.zeroDataSize) {
            try await processor.encryptObject(emptyData, withKey: testKey, destinationFilePath: encryptedPath)
        }
    }

    @Test("Test decryption with wrong key")
    func testDecryptionWithWrongKey() async throws {
        // Arrange
        let processor = createProcessor()
        let testKey = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)
        let testData = TestData(message: "L1FPnexFbjkTBgHQJd6xfpHt9ijLivitf473hyStusffxQJu32xv")
        let encryptedPath = uniqueFilePath(for: "testDecryptionWithWrongKey")

        // Act
        try await processor.encryptObject(testData, withKey: testKey, destinationFilePath: encryptedPath)

        // Assert
        await #expect(throws: CryptographicProcessorError.unableToCreateDecodeStream) {
            let _: TestData = try await processor.decryptObject(
                from: encryptedPath,
                withKey: wrongKey
            )
        }
    }

    @Test("Test decryption with invalid file path")
    func testDecryptionWithInvalidPath() async throws {
        // Arrange
        let processor = createProcessor()
        let testKey = SymmetricKey(size: .bits256)

        // Act & Assert
        await #expect(throws: CryptographicProcessorError.unableToCreateFileStream) {
            let _: TestData = try await processor.decryptObject(
                from: "nonexistent/path",
                withKey: testKey
            )
        }
    }

    @Test("Test encryption with custom configuration")
    func testCustomConfiguration() async throws {
        let customConfig = ProcessorConfiguration(
            filePermissions: FilePermissions(rawValue: 0o600),
            maxInMemoryFileSize: 5000000,
            cpuThreshold: 50000000
        )
        let processor = createProcessor(configuration: customConfig)
        let testKey = SymmetricKey(size: .bits256)
        let testData = TestData(message: "Custom Config Test")
        let encryptedPath = uniqueFilePath(for: "testCustomConfiguration")

        // Act
        try await processor.encryptObject(testData, withKey: testKey, destinationFilePath: encryptedPath)

        let decryptedData: TestData = try await processor.decryptObject(
            from: encryptedPath,
            withKey: testKey
        )

        // Assert
        #expect(decryptedData.message == "Custom Config Test")
        #expect(FileManager.default.fileExists(atPath: encryptedPath))
    }

    @Test("Test large data handling")
    func testLargeDataHandling() async throws {
        // Arrange
        let processor = createProcessor()
        let testKey = SymmetricKey(size: .bits256)
        let largeMessage = String(repeating: "Large Data Test ", count: 1000)
        let testData = TestData(message: largeMessage)
        let encryptedPath = uniqueFilePath(for: "testLargeDataHandling")

        // Act
        try await processor.encryptObject(testData, withKey: testKey, destinationFilePath: encryptedPath)

        let decryptedData: TestData = try await processor.decryptObject(
            from: encryptedPath,
            withKey: testKey
        )

        // Assert
        #expect(decryptedData.message == largeMessage)
        #expect(FileManager.default.fileExists(atPath: encryptedPath))
    }

    @Test("Test encryption with URL source")
    func testEncryptionWithURL() async throws {
        // Arrange
        let processor = createProcessor()
        let testKey = SymmetricKey(size: .bits256)
        let originalMessage = "L1FPnexFbjkTBgHQJd6xfpHt9ijLivitf473hyStusffxQJu32xv"
        let testData = TestData(message: originalMessage)

        // Create a temporary source file
        let sourceFilePath = uniqueFilePath(for: "testEncryptionWithURL_source")
        try testData.data?.write(to: URL(fileURLWithPath: sourceFilePath))

        let encryptedPath = uniqueFilePath(for: "testEncryptionWithURL_encrypted")

        // Act
        try await processor.encryptObject(
            testData,
            withKey: testKey,
            destinationFilePath: encryptedPath
        )

        let decryptedData: TestData = try await processor.decryptObject(
            from: encryptedPath,
            withKey: testKey
        )

        // Assert
        #expect(decryptedData.message == originalMessage)
        #expect(FileManager.default.fileExists(atPath: encryptedPath))
    }

    @Test("Test encryption with very large data")
    func testVeryLargeDataHandling() async throws {
        // Arrange
        let processor = createProcessor()
        let testKey = SymmetricKey(size: .bits256)
        let largeMessage = String(repeating: "Large Data Test ", count: 100000000) // Much larger than the previous test
        let testData = TestData(message: largeMessage)
        let encryptedPath = uniqueFilePath(for: "testVeryLargeDataHandling")

        // Act
        try await processor.encryptObject(testData, withKey: testKey, destinationFilePath: encryptedPath)

        let decryptedData: TestData = try await processor.decryptObject(
            from: encryptedPath,
            withKey: testKey
        )

        // Assert
        #expect(decryptedData.message == largeMessage)
        #expect(FileManager.default.fileExists(atPath: encryptedPath))
    }

    @Test("Test encrypting and decrypting using a generated key using the Archive Encryption Context")
    func testArchiveEncryptionContextKey() async throws {
        // Arrange
        let processor = createProcessor()
        let context = ArchiveEncryptionContext(
            profile: .hkdf_sha256_aesctr_hmac__ecdhe_p256__ecdsa_p256,
            compressionAlgorithm: .lz4
        )
        let testData = TestData(message: "Testing with Archive Encryption Context key")
        let encryptedPath = uniqueFilePath(for: "testArchiveEncryptionContext")

        // Generate a key from the context
        let contextKey = try context.generateSymmetricKey()

        // Act
        try await processor.encryptObject(
            testData,
            withKey: contextKey,
            destinationFilePath: encryptedPath
        )

        let decryptedData: TestData = try await processor.decryptObject(
            from: encryptedPath,
            withKey: contextKey
        )

        // Assert
        #expect(decryptedData.message == testData.message)
        #expect(FileManager.default.fileExists(atPath: encryptedPath))

        // Verify that using a different context key fails
        let differentContext = ArchiveEncryptionContext(
            profile: .hkdf_sha256_aesctr_hmac__ecdhe_p256__ecdsa_p256,
            compressionAlgorithm: .lz4
        )
        // Generate a different key from the context
        let differentContextKey = try differentContext.generateSymmetricKey()
        await #expect(throws: CryptographicProcessorError.unableToCreateDecodeStream) {
            let _: TestData = try await processor.decryptObject(
                from: encryptedPath,
                withKey: differentContextKey
            )
        }
    }

    @Test("Test encryption with 256-bit key")
    func testEncryptionWith256BitKey() async throws {
        // Arrange
        let processor = createProcessor()
        let testKey = SymmetricKey(size: .bits256)
        let testData = TestData(message: "Testing with 256-bit key encryption")
        let encryptedPath = uniqueFilePath(for: "test256BitKey")

        // Act
        try await processor.encryptObject(
            testData,
            withKey: testKey,
            destinationFilePath: encryptedPath
        )

        let decryptedData: TestData = try await processor.decryptObject(
            from: encryptedPath,
            withKey: testKey
        )

        // Assert
        #expect(decryptedData.message == testData.message)
        #expect(FileManager.default.fileExists(atPath: encryptedPath))
    }

    @Test("Test cross-key encryption failure")
    func testCrossKeyEncryptionFailure() async throws {
        // Arrange
        let processor = createProcessor()
        let encryptionKey = SymmetricKey(size: .bits256)
        let decryptionKey = SymmetricKey(size: .bits128)
        let testData = TestData(message: "Testing cross-key encryption")
        let encryptedPath = uniqueFilePath(for: "testCrossKeyEncryption")

        // Act
        try await processor.encryptObject(
            testData,
            withKey: encryptionKey,
            destinationFilePath: encryptedPath
        )

        // Assert
        await #expect(throws: CryptographicProcessorError.unableToCreateDecodeStream) {
            let _: TestData = try await processor.decryptObject(
                from: encryptedPath,
                withKey: decryptionKey
            )
        }
    }
}


