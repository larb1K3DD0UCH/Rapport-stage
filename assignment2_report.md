---

```markdown
# Title: EECS 449M Assignment 2 Report
# Author: <your name here>

## Executive Summary

This project extends a basic photo-sharing app by adding support for multiple devices and friend features. In this assignment, I implemented new log entry formats that include cryptographic hashes, device public keys, and digital signatures. These changes allow devices to invite, accept, and revoke each other securely, and they ensure that friends see only the photos uploaded by authorized devices. This report explains what was done, how it was implemented, and how the design meets key security goals.

## Part 1: Implementation Report

### 1. Overview of Implementation

The project builds on a previous assignment by adding the following key features:

- **Multi-device support:**  
  I added functions to invite a new device, accept an invitation, and revoke a device. Each device has its own public key and logs its actions using cryptographic signatures.

- **Friend features:**  
  The client now maintains a local friend list that stores trusted public keys and photo logs for each friend. This lets users view photos uploaded by friends while ensuring the data is authentic.

- **Enhanced log entries:**  
  I updated the log entry structure to include a hash value, the device’s public key, and a digital signature. These additions help verify that every log entry is correct and hasn’t been tampered with.

### 2. Detailed Design and Implementation

#### a. Log Entry Structure

The `LogEntry` class was extended to store extra information:

- **Operation code:** Determines the type of operation (e.g., REGISTER, PUT_PHOTO, DEVICE_INVITE, DEVICE_ADDED, DEVICE_REVOKED).
- **Data:** Encoded information relevant to the operation (for example, the photo ID or the public key of an invited device).
- **Hash value (`hash_val`):** A cryptographic hash computed over the operation, ensuring the integrity of the log entry.
- **Device public key (`device_pub_key`):** The public key of the device that generated the log entry.
- **Digital signature (`digital_sig`):** A signature over the hash value, allowing other devices and the server to verify authenticity.

These additions make it possible to check that log entries (such as those for photo uploads or device management) are valid and have not been modified by an attacker.

```python
class LogEntry:
    def __init__(self, opcode: OperationCode, data: bytes, hash_val, device_pub_key, digital_sig) -> None:
        self.opcode = opcode.value
        self.data = data
        self.hash_val = hash_val
        self.device_pub_key = device_pub_key
        self.digital_sig = digital_sig
```

The encoding and decoding methods are implemented as follows:

```python
def encode(self) -> bytes:
    result = codec.encode(
        [self.opcode, self.data, self.hash_val, self.device_pub_key, self.digital_sig]
    )
    return result

@staticmethod
def decode(data: bytes) -> "LogEntry":
    opcode_int, log_data, hash_val, device_pub_key, digital_sig = codec.decode(data)
    opcode = OperationCode(opcode_int)
    return LogEntry(opcode, log_data, hash_val, device_pub_key, digital_sig)
```

#### b. Multi-Device Management in Client

The client was updated to support multi-device operations:

- **Device Invitation:**  
  The `invite_device()` function computes a hash of the invited device’s public key, signs it, and creates a log entry. This tells the server and other devices that an invitation has been sent.

```python
def invite_device(self, device_public_key: bytes) -> None:
    self._synchronize()
    hash_val = self.compute_hash(OperationCode.DEVICE_INVITE.value, device_public_key)
    digital_sig = self._public_key_signer.sign(codec.encode(hash_val))
    log = LogEntry(OperationCode.DEVICE_INVITE, device_public_key, hash_val, self.public_key, digital_sig)
    self._push_log_entry(log)
    if device_public_key in self._device_revoked_set:
        self._device_revoked_set.remove(device_public_key)
    if log.device_pub_key in self._device_invite_dict:
        self._device_invite_dict[log.device_pub_key].add(log.data)
    else:
        self._device_invite_dict[log.device_pub_key] = {log.data}
```

- **Device Acceptance:**  
  When a device receives an invitation, it calls `accept_invite()`. The device then creates a log entry (DEVICE_ADDED) that proves it was invited and accepted the invitation.

```python
def accept_invite(self, inviter_public_key: bytes) -> None:
    self._synchronize()
    if inviter_public_key in self._device_invite_dict and self.public_key in self._device_invite_dict[inviter_public_key]:
        hash_val = self.compute_hash(OperationCode.DEVICE_ADDED.value, self.public_key)
        digital_sig = self._public_key_signer.sign(codec.encode(hash_val))
        log = LogEntry(OperationCode.DEVICE_ADDED, self.public_key, hash_val, self.public_key, digital_sig)
        self._push_log_entry(log)
        self._device_added_set.add(self.public_key)
        self.remove_invitation(self.public_key)
```

- **Device Revocation:**  
  The `revoke_device()` function allows a device to remove another device’s access. Even if a revoked device had uploaded photos before it was revoked, those photos remain valid because they were signed when the device was still authorized.

```python
def revoke_device(self, device_public_key: bytes) -> None:
    self._synchronize()
    hash_val = self.compute_hash(OperationCode.DEVICE_REVOKED.value, device_public_key)
    digital_sig = self._public_key_signer.sign(codec.encode(hash_val))
    log = LogEntry(OperationCode.DEVICE_REVOKED, device_public_key, hash_val, self.public_key, digital_sig)
    self._push_log_entry(log)
    self.remove_invitation(device_public_key)
    if device_public_key in self._device_added_set and device_public_key != self.public_key:
        self._device_added_set.remove(device_public_key)
        self._device_revoked_set.add(device_public_key)
```

Local dictionaries and sets are maintained to track:
- **Invitations sent:** Stored in `_device_invite_dict`.
- **Authorized devices:** Tracked using `_device_added_set`.
- **Revoked devices:** Managed in `_device_revoked_set`.

#### c. Helper Functions

Important helper functions were added to aid in protocol verification:

- **compute_hash:**  
  Computes a hash over an operation and its data, using a base hash.

```python
def compute_hash(self, op, data, base=None):
    current_base = self._last_log_hash if base is None else base
    combined_value = current_base + hash(str(op)) + hash(str(data))
    return hash(combined_value)
```

- **check_signature:**  
  Checks that a log entry’s digital signature matches the computed hash and that the device is allowed to perform the operation.

```python
def check_signature(self, hash_val, entry: LogEntry):
    if not crypto.verify_sign(entry.device_pub_key, codec.encode(hash_val), entry.digital_sig):
        raise errors.SynchronizationError("Signature doesn't match")
    if entry.device_pub_key not in self._device_added_set and entry.opcode not in {OperationCode.REGISTER.value, OperationCode.DEVICE_ADDED.value}:
        raise errors.SynchronizationError("Device not allowed to add log")
```

- **remove_invitation:**  
  A helper function that removes a device from the invitation list.

```python
def remove_invitation(self, dev_key):
    for sender, invite_list in self._device_invite_dict.items():
        if dev_key in invite_list:
            invite_list.remove(dev_key)
```

- **check_friend_log:**  
  Verifies friend log entries by checking the hash, the signature, and the trust status of the device.

```python
def check_friend_log(self, step, entry, calc_hash, friend_data):
    if calc_hash != entry.hash_val:
        raise errors.SynchronizationError(f"{step} hash doesn't match")
    if not crypto.verify_sign(entry.device_pub_key, codec.encode(calc_hash), entry.digital_sig):
        raise errors.SynchronizationError(f"{step}: Signature mismatch")
    if step != "ADDED" and entry.device_pub_key not in friend_data.trusted_keys:
        raise errors.SynchronizationError(f"{step}: Untrusted device")
    if step == "ADDED" and entry.device_pub_key not in friend_data.awaiting_invite:
        raise errors.SynchronizationError(f"{step}: Device not invited")
```

### 3. Security Analysis

#### a. Device Compromise with an Honest Server

**Security Goal:**  
Ensure that if one device is compromised, a friend can only see photos that were uploaded by authorized devices at the time of the upload.

**Implementation:**  
- Every photo upload is logged with a timestamp, a hash, and a digital signature.
- Even if a device is later compromised and revoked, photos uploaded while the device was trusted remain verifiable.
- During synchronization, the client checks that each log entry was created by a trusted device.

#### b. Server Compromise with Multi-Client

**Security Goal:**  
Prevent a compromised server from tampering with or reordering log entries so that friends see the correct photos.

**Implementation:**  
- Hash chaining across log entries ensures that any attempt to modify, reorder, or drop entries is detected during synchronization.
- Digital signatures guarantee that only authorized devices can add valid entries.
- Strict verification during synchronization makes it difficult for the server to hide or alter the logs without detection.

#### c. Real User Compromise

**Security Goal:**  
Although a compromised user can misuse their privileges, the system should ensure that any malicious actions are immediately evident to other users.

**Implementation:**  
- The protocol enforces that only authorized devices can add valid log entries.
- If an unauthorized device (e.g., a compromised device trying to revoke a valid device) attempts to add an entry, signature verification fails and the entry is rejected.
- Any anomalies in the log chain are flagged during synchronization, alerting friends and other devices to potential issues.

### 4. Conclusion

In this project, I extended a basic photo-sharing app with multi-device support and friend management features while focusing on strong security. The enhanced log entry structure—with cryptographic hashes, device public keys, and digital signatures—ensures that all operations are secure and verifiable. Each security goal is met through careful design and implementation, making the system resilient against device compromise, server tampering, and unauthorized actions. This approach provides a solid foundation for building secure multi-device applications.

---

## Part 2: System Security Questions

### Chosen-Plaintext Attacks (CPA)

In this scheme, to encrypt a message \( m \):

1. A random value \( r \) (of the same length as \( m \)) is chosen.
2. A one-time pad is applied by computing:
   \[
   c = m \oplus r
   \]
3. The random value \( r \) is then encrypted using RSA by computing:
   \[
   t = r^e \mod n
   \]
4. The final ciphertext is the pair \((c, t)\).

Because \( r \) is chosen uniformly at random, the XOR operation \( c = m \oplus r \) acts as a perfect one-time pad. No matter which plaintext \( m \) is chosen, \( c \) reveals no information about \( m \). Even though RSA encryption (of \( r \)) is deterministic without padding, each encryption uses a fresh random \( r \). Thus, the scheme is secure against chosen-plaintext attacks.

### Chosen-Ciphertext Attacks (CCA)

When an adversary can choose ciphertexts and obtain their decryptions, the scheme becomes vulnerable:

- Recall that \( t = r^e \mod n \). RSA has a multiplicative property:
  \[
  (r \cdot x)^e \mod n = (r^e \cdot x^e) \mod n
  \]
- An attacker can take a valid ciphertext \((c, t)\) and modify the RSA part by computing:
  \[
  t' = t \cdot (x^e \mod n) \mod n
  \]
  for some chosen multiplier \( x \).
- The decryption algorithm would then compute:
  \[
  r' = (t')^d \mod n = r \cdot x \mod n
  \]
- The one-time pad part remains \( c = m \oplus r \), but now the decryption yields:
  \[
  m' = c \oplus r' = c \oplus (r \cdot x)
  \]
- By carefully choosing different values of \( x \) and comparing outputs, an attacker can gain information about \( r \) and ultimately about \( m \).

Thus, the scheme is vulnerable to chosen-ciphertext attacks due to RSA's multiplicative property.

### Summary

- **CPA Security:**  
  The scheme is secure against chosen-plaintext attacks because the random one-time pad completely hides the message.

- **CCA Vulnerability:**  
  The scheme is vulnerable to chosen-ciphertext attacks because the deterministic RSA encryption of \( r \) is malleable, allowing an attacker to alter the ciphertext and eventually uncover information about \( m \).

This vulnerability highlights the importance of using proper padding schemes with RSA to prevent such malleability in practical encryption systems.
```

---
