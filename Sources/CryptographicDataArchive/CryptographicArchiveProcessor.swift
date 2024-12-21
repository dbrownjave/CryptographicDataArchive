// The Swift Programming Language
// https://docs.swift.org/swift-book

//
//  CryptographicArchiveProcessor.swift
//  CryptographicArchiveProcessor
//
//  Created by Dorian Brown on 12/19/24.
//

import AppleArchive
import CryptoKit
import Foundation
import System


/// Encrypt the contents of a string and save the result to the file system, then decrypt and recreate the string from the archive file using Apple Encrypted Archive.
/// 
// MARK: - Public Protocols & Types


/// Configuration options for the CryptographicArchiveProcessor
public struct ProcessorConfiguration {
    /// Maximum file size to process in memory (in bytes)
    public let maxInMemoryFileSize: UInt64
    
    /// CPU threshold for processing (in bytes)
    public let cpuThreshold: UInt64
   
    /// An object that encapsulates all parameters, keys, and data necessary to open an encrypted archive for both encryption and decryption streams
    public let encryptionContext: ArchiveEncryptionContext
    
    /// File permissions for created files
    public let filePermissions: FilePermissions
    
    /// File options for reading
    public let readOpenOptions: FileDescriptor.OpenOptions
    
    /// File options for writing
    public let writeOpenOptions: FileDescriptor.OpenOptions

    public init(
        encryptionContext: ArchiveEncryptionContext = .init(profile:  .hkdf_sha256_aesctr_hmac__symmetric__none, compressionAlgorithm: .lzfse),
        filePermissions: FilePermissions = FilePermissions(rawValue: 0o644),
        readOpenOptions: FileDescriptor.OpenOptions = [],
        writeOpenOptions: FileDescriptor.OpenOptions = [.create, .truncate],
        maxInMemoryFileSize: UInt64 = 1_0000_000,
        cpuThreshold: UInt64 = 10_0000_000
    ) {
        self.encryptionContext = encryptionContext
        self.maxInMemoryFileSize = maxInMemoryFileSize
        self.cpuThreshold = cpuThreshold
        self.filePermissions = filePermissions
        self.readOpenOptions = readOpenOptions
        self.writeOpenOptions = writeOpenOptions
    }
}

/// Protocol for objects that can be encrypted and archived
public protocol CryptographicArchivable {
    /// A property that provides the `Data` representation of the conforming object
    var data: Data? { get }

    /// Initializes the object from `Data`
    init?(data: Data)
}

/// Errors that can occur during cryptographic processing
public enum CryptographicProcessorError: LocalizedError {
    case unableToCreateDecodeStream
    case unableToGetHeaderField
    case zeroDataSize
    case unableToCreateFileStream
    case unableToCreateEncryptionStream
    case unableToCreateDecryptionContext
    case invalidConfiguration

    public var errorDescription: String? {
        switch self {
        case .unableToCreateDecodeStream:
            return "Failed to create decode stream"
        case .unableToGetHeaderField:
            return "Failed to get header field"
        case .zeroDataSize:
            return "Data size is zero"
        case .unableToCreateFileStream:
            return "Failed to create file stream"
        case .unableToCreateEncryptionStream:
            return "Failed to create encryption stream"
        case .unableToCreateDecryptionContext:
            return "Failed to create decryption context"
        case .invalidConfiguration:
            return "Invalid processor configuration"
        }
    }
}

// MARK: - Main Processor Class

public class CryptographicArchiveProcessor: ObservableObject {
    private let configuration: ProcessorConfiguration

    /// Initialize with custom configuration
    public init(configuration: ProcessorConfiguration = .init()) {
        self.configuration = configuration
    }

    // MARK: - Public Methods

    /// Encrypt an object and save it to a file
    /// - Parameters:
    ///   - object: Object conforming to CryptographicArchivable
    ///   - key: Encryption key
    ///   - destinationFilePath: Path where encrypted file will be saved
    /// - Returns: Success status
    @discardableResult
    public func encryptObject(
        _ object: CryptographicArchivable,
        withKey key: SymmetricKey,
        destinationFilePath: String
    ) async throws -> Bool {
        guard let objectData = object.data, !objectData.isEmpty else {
            throw CryptographicProcessorError.zeroDataSize
        }

        // Use detached task to avoid data races
        do {
            try encryptUsingStream(
                source: .data(objectData),
                withKey: key,
                destinationFilePath: destinationFilePath
            )
            return true
        } catch {
            throw error
        }
    }

    /// Decrypt an object from a file
    /// - Parameters:
    ///   - sourceFilePath: Path to encrypted file
    ///   - key: Decryption key
    /// - Returns: Decrypted object of specified type
    public func decryptObject<T: CryptographicArchivable>(
        from sourceFilePath: String,
        withKey key: SymmetricKey
    ) async throws -> T {
        let temporaryDecryptedPath = try createTemporaryFilePath()

        // Use detached task to avoid data races
        do {
            try decryptFile(
                from: sourceFilePath,
                withKey: key,
                destinationFilePath: temporaryDecryptedPath
            )
        } catch {
            throw error
        }

        let decryptedData = try Data(contentsOf: URL(fileURLWithPath: temporaryDecryptedPath))
        try deleteFile(at: temporaryDecryptedPath)

        guard let object = T(data: decryptedData) else {
            throw CryptographicProcessorError.unableToGetHeaderField
        }
        return object
    }

    // Unified function to handle both in-memory and streaming encryption
    private func encryptUsingStream(
        source: Either<Data, URL>,
        withKey key: SymmetricKey,
        destinationFilePath: String
    ) throws {
        // Create the encryption context
        let context = configuration.encryptionContext
        try context.setSymmetricKey(key)

        // Create the destination file stream
        guard let destinationFileStream = ArchiveByteStream.fileStream(
            path: .init(destinationFilePath),
            mode: .writeOnly,
            options: configuration.writeOpenOptions,
            permissions: configuration.filePermissions) else {
            throw CryptographicProcessorError.unableToCreateFileStream
        }

        // Handle in-memory Data or URL
        let sourceFilePath: String
        var temporaryFilePath: String?

        switch source {
        case let .data(data):
            // Write Data to a temporary file
            temporaryFilePath = try createTemporaryFilePath()
            try data.write(to: URL(fileURLWithPath: temporaryFilePath!))
            sourceFilePath = temporaryFilePath!
        case let .url(fileURL):
            sourceFilePath = fileURL.path
        }

        // Create the source file stream
        guard let sourceFileStream = ArchiveByteStream.fileStream(
            path: .init(sourceFilePath),
            mode: .readOnly,
            options: configuration.readOpenOptions,
            permissions: configuration.filePermissions) else {
            if let tempPath = temporaryFilePath {
                try? deleteFile(at: tempPath)
            }
            throw CryptographicProcessorError.unableToCreateFileStream
        }

        // Create the encryption output stream
        guard let encryptionStream = ArchiveByteStream.encryptionStream(
            writingTo: destinationFileStream,
            encryptionContext: context) else {
            if let tempPath = temporaryFilePath {
                try? deleteFile(at: tempPath)
            }
            throw CryptographicProcessorError.unableToCreateEncryptionStream
        }

        // Process the source file stream to the destination
        _ = try ArchiveByteStream.process(readingFrom: sourceFileStream, writingTo: encryptionStream)

        // Close streams
        try encryptionStream.close()
        try destinationFileStream.close()
        try sourceFileStream.close()

        // Clean up temporary file
        if let tempPath = temporaryFilePath {
            try deleteFile(at: tempPath)
        }
    }

    // Function to decrypt a file and write it to a destination file
    private func decryptFile(
        from sourceFilePath: String,
        withKey key: SymmetricKey,
        destinationFilePath: String
    ) throws {
        guard let sourceFileStream = ArchiveByteStream.fileStream(
            path: .init(sourceFilePath),
            mode: .readOnly,
            options: configuration.readOpenOptions,
            permissions: configuration.filePermissions) else {
            throw CryptographicProcessorError.unableToCreateFileStream
        }

        guard let decryptionContext = ArchiveEncryptionContext(from: sourceFileStream) else {
            throw CryptographicProcessorError.unableToCreateDecryptionContext
        }

        try decryptionContext.setSymmetricKey(key)

        guard let decryptionStream = ArchiveByteStream.decryptionStream(
            readingFrom: sourceFileStream,
            encryptionContext: decryptionContext) else {
            throw CryptographicProcessorError.unableToCreateDecodeStream
        }

        guard let destinationFileStream = ArchiveByteStream.fileStream(
            path: .init(destinationFilePath),
            mode: .writeOnly,
            options: configuration.writeOpenOptions,
            permissions: configuration.filePermissions) else {
            throw CryptographicProcessorError.unableToCreateFileStream
        }

        _ = try ArchiveByteStream.process(readingFrom: decryptionStream, writingTo: destinationFileStream)

        try destinationFileStream.close()
        try sourceFileStream.close()
        try decryptionStream.close()
    }

    // MARK: - Temporary File Management

    /// Create a unique temporary file path
    private func createTemporaryFilePath() throws -> String {
        let temporaryDirectory = FileManager.default.temporaryDirectory
        let uniqueFileName = UUID().uuidString
        let temporaryFilePath = temporaryDirectory.appendingPathComponent(uniqueFileName).path

        // Ensure the temporary directory exists
        if !FileManager.default.fileExists(atPath: temporaryDirectory.path) {
            try FileManager.default.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true, attributes: nil)
        }

        return temporaryFilePath
    }

    /// Delete a file at a specified path
    private func deleteFile(at path: String) throws {
        if FileManager.default.fileExists(atPath: path) {
            try FileManager.default.removeItem(atPath: path)
        }
    }
}

// MARK: - Extensions

extension CryptographicArchiveProcessor {
    public enum Either<L, R> {
        case data(L)
        case url(R)
    }
}
