import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

import '../../auth/auth_config.dart';
import '../wallet_port.dart';

/// What a SEP-10 challenge must match before any wallet prompt (design D11).
final class ChallengeExpectations {
  const ChallengeExpectations({
    required this.serverSigningKey,
    required this.homeDomain,
    required this.webAuthDomain,
    required this.networkPassphrase,
  });

  factory ChallengeExpectations.fromConfig(AuthConfig config) =>
      ChallengeExpectations(
        serverSigningKey: config.serverSigningKey,
        homeDomain: config.homeDomain,
        webAuthDomain: config.webAuthDomain,
        networkPassphrase: config.networkPassphrase,
      );

  /// The server's public signing account (`G…`).
  final String serverSigningKey;
  final String homeDomain;
  final String webAuthDomain;
  final String networkPassphrase;
}

/// The client-side SEP-10 check (design D12, scenario W39).
///
/// `stellar_flutter_sdk`'s `WebAuth.validateChallenge` covers the sequence,
/// operation types and sources, home domain, `web_auth_domain` value, time
/// bounds and the single server signature. This adds what it leaves out: a
/// canonical envelope, the wallet's network, the transaction source, a
/// required `web_auth_domain` operation, and time bounds read from [clock].
final class Sep10ChallengeCheck {
  const Sep10ChallengeCheck({this.clock = DateTime.now});

  /// The client clock the time bounds are checked against.
  final DateTime Function() clock;

  /// Returns the parsed challenge when every check passes.
  ///
  /// Throws [WalletWrongNetwork] when [walletNetwork] is not the expected
  /// network, and [WalletInvalidChallenge] for any other failure. Nothing
  /// here prompts the wallet.
  Transaction validate(
    String challengeXdr, {
    required ChallengeExpectations expected,
    required String account,
    required String? walletNetwork,
  }) {
    if (walletNetwork != expected.networkPassphrase) {
      throw const WalletWrongNetwork();
    }
    final tx = _parseCanonical(challengeXdr);
    if (tx.sourceAccount.ed25519AccountId != expected.serverSigningKey) {
      throw const WalletInvalidChallenge(ChallengeRejection.source);
    }
    _validateWithSdk(challengeXdr, expected, account);
    _requireWebAuthDomainOperation(tx);
    _requireCurrentTimeBounds(tx);
    return tx;
  }

  Transaction _parseCanonical(String xdr) {
    try {
      final parsed = AbstractTransaction.fromEnvelopeXdrString(xdr);
      if (parsed is Transaction && parsed.toEnvelopeXdrBase64() == xdr) {
        return parsed;
      }
    } on Object {
      // Falls through to the typed rejection.
    }
    throw const WalletInvalidChallenge(ChallengeRejection.malformed);
  }

  void _validateWithSdk(
    String xdr,
    ChallengeExpectations expected,
    String account,
  ) {
    final webAuth = WebAuth(
      Uri.https(expected.webAuthDomain).toString(),
      Network(expected.networkPassphrase),
      expected.serverSigningKey,
      expected.homeDomain,
    );
    // The SDK reads the system clock. The grace period cancels the gap to
    // [clock], and [_requireCurrentTimeBounds] applies the strict check.
    final skew = DateTime.now().difference(clock()).inSeconds.abs();
    try {
      webAuth.validateChallenge(xdr, account, null, skew);
    } on ChallengeValidationError catch (error) {
      throw WalletInvalidChallenge(_rejectionOf(error));
    } on Object {
      throw const WalletInvalidChallenge(ChallengeRejection.malformed);
    } finally {
      webAuth.httpClient.close();
    }
  }

  ChallengeRejection _rejectionOf(ChallengeValidationError error) =>
      switch (error) {
        ChallengeValidationErrorInvalidSeqNr() => ChallengeRejection.sequence,
        ChallengeValidationErrorInvalidSourceAccount() =>
          ChallengeRejection.operationSource,
        ChallengeValidationErrorInvalidOperationType() =>
          ChallengeRejection.operationType,
        ChallengeValidationErrorInvalidHomeDomain() =>
          ChallengeRejection.homeDomain,
        ChallengeValidationErrorInvalidWebAuthDomain() =>
          ChallengeRejection.webAuthDomain,
        ChallengeValidationErrorInvalidTimeBounds() =>
          ChallengeRejection.timeBounds,
        ChallengeValidationErrorInvalidSignature() =>
          ChallengeRejection.serverSignature,
        _ => ChallengeRejection.malformed,
      };

  /// The SDK checks a `web_auth_domain` value only when the operation is
  /// present; the app requires it.
  void _requireWebAuthDomainOperation(Transaction tx) {
    final present = tx.operations
        .skip(1)
        .any(
          (op) => op is ManageDataOperation && op.name == 'web_auth_domain',
        );
    if (!present) {
      throw const WalletInvalidChallenge(ChallengeRejection.webAuthDomain);
    }
  }

  void _requireCurrentTimeBounds(Transaction tx) {
    final bounds = tx.preconditions?.timeBounds;
    final now = clock().millisecondsSinceEpoch ~/ 1000;
    if (bounds == null ||
        bounds.maxTime == 0 ||
        now < bounds.minTime ||
        now > bounds.maxTime) {
      throw const WalletInvalidChallenge(ChallengeRejection.timeBounds);
    }
  }
}
