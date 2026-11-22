// asiri-touchid: approval keys in the Secure Enclave.
//
// The key is a P-256 key created inside this Mac's Secure Enclave. Its
// private half never leaves it; the file KEYFILE holds an encrypted handle
// that only this Mac's Secure Enclave can use. Every signature needs Touch ID
// or the Mac's password.
//
//   asiri-touchid available            exit 0 if this Mac can hold a key
//   asiri-touchid create KEYFILE       new key; prints its public key (base64 PKIX DER)
//   asiri-touchid pubkey KEYFILE       prints the public key
//   asiri-touchid sign KEYFILE         signs the asiri statement on stdin; prints base64 DER
//   asiri-touchid describe             prints what the statement on stdin allows
//
// sign shows the person a sentence made from the statement itself, so what
// they read is what they sign, and it refuses anything that isn't an asiri
// statement. Exit codes: 0 ok, 1 error, 2 usage, 3 not approved (cancelled
// or failed), 4 no Secure Enclave or no way to authenticate.
//
// Build: xcrun swiftc -O macos/touchid/main.swift -o bin/asiri-touchid
import CryptoKit
import Foundation
import LocalAuthentication
import Security

func fail(_ msg: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write(("asiri-touchid: " + msg + "\n").data(using: .utf8)!)
    exit(code)
}

// describe mirrors approvalkey.Describe in Go; testdata keeps them in step.
func describe(_ text: String) -> String? {
    guard let nl = text.firstIndex(of: "\n") else { return nil }
    let header = String(text[..<nl])
    var body = String(text[text.index(after: nl)...])
    if body.hasSuffix("\n") { body.removeLast() }
    var f: [String: String] = [:]
    for line in body.components(separatedBy: "\n") {
        guard let r = line.range(of: ": ") else { return nil }
        let k = String(line[..<r.lowerBound]), v = String(line[r.upperBound...])
        if f[k] != nil { return nil }
        f[k] = v
    }
    switch header {
    case "asiri approval v1":
        let when = ["once": "once", "15m": "for 15 minutes", "1h": "for 1 hour"][f["decision"] ?? ""]
        guard let when, let client = f["client"], !client.isEmpty, let secret = f["secret"], !secret.isEmpty,
              let program = f["program"], !program.isEmpty else { return nil }
        switch f["action"] {
        case "use":
            return "allow \(client) to use \(secret) with \(program) \(when)"
        case "ssh":
            guard let host = f["host"], !host.isEmpty else { return nil }
            return "allow \(client) to sign in to host \(host) with \(secret) using \(program) \(when)"
        default:
            return nil // an action this helper doesn't know: refuse to sign it
        }
    case "asiri approval key v1":
        guard let key = f["key"], !key.isEmpty else { return nil }
        return "use this Mac to approve asiri requests (key \(key))"
    default:
        return nil
    }
}

func readStdin() -> Data {
    let d = FileHandle.standardInput.readDataToEndOfFile()
    if d.count > 64 << 10 { fail("statement too long") }
    return d
}

func loadKey(_ path: String, _ ctx: LAContext? = nil) -> SecureEnclave.P256.Signing.PrivateKey {
    do {
        let blob = try Data(contentsOf: URL(fileURLWithPath: path))
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
    } catch {
        fail("can't load the key in \(path): \(error.localizedDescription)")
    }
}

let args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else { fail("usage: asiri-touchid available|create|pubkey|sign|describe", 2) }

switch (cmd, args.count) {
case ("available", 1):
    guard SecureEnclave.isAvailable else { fail("this Mac has no Secure Enclave", 4) }
    var err: NSError?
    guard LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
        fail("can't ask for Touch ID or the password: \(err?.localizedDescription ?? "unknown")", 4)
    }
    print("ok")

case ("create", 2):
    guard SecureEnclave.isAvailable else { fail("this Mac has no Secure Enclave", 4) }
    var cfErr: Unmanaged<CFError>?
    // userPresence: Touch ID, or the Mac's password when Touch ID can't be
    // used (lid closed, no enrolled finger). Never without the person.
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .userPresence], &cfErr) else {
        fail("access control: \(cfErr!.takeRetainedValue())")
    }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let url = URL(fileURLWithPath: args[1])
        guard FileManager.default.createFile(atPath: url.path, contents: nil,
                                             attributes: [.posixPermissions: 0o600]) else {
            fail("can't create \(url.path)")
        }
        try key.dataRepresentation.write(to: url)
        print(key.publicKey.derRepresentation.base64EncodedString())
    } catch {
        fail("create: \(error.localizedDescription)")
    }

case ("pubkey", 2):
    print(loadKey(args[1]).publicKey.derRepresentation.base64EncodedString())

case ("describe", 1):
    guard let text = String(data: readStdin(), encoding: .utf8), let s = describe(text) else {
        print("error")
        exit(1)
    }
    print(s)

case ("sign", 2):
    let msg = readStdin()
    guard let text = String(data: msg, encoding: .utf8), let reason = describe(text) else {
        fail("refusing to sign: not an asiri statement")
    }
    let ctx = LAContext()
    ctx.localizedReason = reason
    ctx.localizedCancelTitle = "Don't allow"
    let key = loadKey(args[1], ctx)
    do {
        print(try key.signature(for: msg).derRepresentation.base64EncodedString())
    } catch let e as LAError {
        fail("not approved: \(e.localizedDescription)", 3)
    } catch {
        fail("not approved: \(error.localizedDescription)", 3)
    }

default:
    fail("usage: asiri-touchid available|create KEYFILE|pubkey KEYFILE|sign KEYFILE|describe", 2)
}
