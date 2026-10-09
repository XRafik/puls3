import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:puls3_flutter/src/wallet/sep10/sep10_challenge_check.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

/// The server key of `docs/architecture/examples/sep10/` (32 bytes of 0x07).
/// A test vector, not a credential.
final KeyPair vectorServerKey = KeyPair.fromSecretSeedList(
  Uint8List.fromList(List.filled(32, 7)),
);

/// The committed server vector, read from the repository docs.
Map<String, dynamic> readSep10Vector() =>
    jsonDecode(
          File(
            '../docs/architecture/examples/sep10/challenge.json',
          ).readAsStringSync(),
        )
        as Map<String, dynamic>;

/// Fixed clock for hand-built challenges.
final DateTime challengeNow = DateTime.utc(2026, 10, 9, 12);

const homeDomain = 'puls3.app';
const webAuthDomain = 'auth.puls3.app';

ChallengeExpectations expectationsFor({
  KeyPair? server,
  String home = homeDomain,
  String web = webAuthDomain,
  String networkPassphrase = 'Test SDF Network ; September 2015',
}) => ChallengeExpectations(
  serverSigningKey: (server ?? vectorServerKey).accountId,
  homeDomain: home,
  webAuthDomain: web,
  networkPassphrase: networkPassphrase,
);

/// A SEP-10 challenge as the server builds it, with knobs to break one rule
/// at a time.
String buildChallenge({
  required String account,
  KeyPair? server,
  String home = homeDomain,
  String web = webAuthDomain,
  Network? network,
  int sequence = 0,
  bool timeBounds = true,
  DateTime? now,
  List<Operation> extra = const [],
  KeyPair? signer,
  String? transactionSource,
  bool includeWebAuthDomain = true,
}) {
  final serverKey = server ?? vectorServerKey;
  final start = now ?? challengeNow;
  final nonce = base64Encode(List<int>.generate(48, (i) => i + 1));
  final builder =
      TransactionBuilder(
        Account(
          transactionSource ?? serverKey.accountId,
          BigInt.from(sequence - 1),
        ),
      )..addOperation(
        ManageDataOperationBuilder(
          '$home auth',
          Uint8List.fromList(utf8.encode(nonce)),
        ).setSourceAccount(account).build(),
      );
  if (includeWebAuthDomain) {
    builder.addOperation(
      ManageDataOperationBuilder(
        'web_auth_domain',
        Uint8List.fromList(utf8.encode(web)),
      ).setSourceAccount(serverKey.accountId).build(),
    );
  }
  extra.forEach(builder.addOperation);
  if (timeBounds) {
    final seconds = start.millisecondsSinceEpoch ~/ 1000;
    builder.addPreconditions(
      TransactionPreconditions()
        ..timeBounds = TimeBounds(seconds, seconds + 900),
    );
  }
  final tx = builder.build()
    ..sign(signer ?? serverKey, network ?? Network.TESTNET);
  return tx.toEnvelopeXdrBase64();
}
