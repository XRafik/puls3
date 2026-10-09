import 'package:flutter_test/flutter_test.dart';
import 'package:puls3_flutter/src/wallet/freighter/freighter_bridge.dart';
import 'package:puls3_flutter/src/wallet/freighter/freighter_wallet.dart';
import 'package:puls3_flutter/src/wallet/sep10/sep10_challenge_check.dart';
import 'package:puls3_flutter/src/wallet/wallet_port.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

import 'sep10_fixtures.dart';

/// Stands in for Freighter: signs whatever it is given with [key], unless a
/// test swaps the answer through [signer].
class ChallengeBridge implements FreighterBridge {
  ChallengeBridge(this.key);

  final KeyPair key;
  String? activeAddress;
  String Function(String xdr)? signer;
  int signCalls = 0;

  FreighterSession get _session => FreighterSession(
    address: activeAddress ?? key.accountId,
    networkPassphrase: stellarTestnetPassphrase,
  );

  @override
  Future<FreighterSession> connect() async => _session;

  @override
  Future<FreighterSession> currentSession() async => _session;

  @override
  Future<String> signTransaction(
    String xdr,
    String networkPassphrase,
    String address,
  ) async {
    signCalls++;
    final custom = signer;
    if (custom != null) return custom(xdr);
    return _signWith(key, xdr);
  }

  @override
  Future<AuthEntrySignature> signAuthEntryPreimage(
    String preimageXdr,
    String networkPassphrase,
    String address,
  ) => throw UnimplementedError();
}

String _signWith(KeyPair key, String xdr) {
  final tx = AbstractTransaction.fromEnvelopeXdrString(xdr) as Transaction;
  tx.sign(key, Network.TESTNET);
  return tx.toEnvelopeXdrBase64();
}

void main() {
  late KeyPair walletKey;
  late ChallengeBridge bridge;
  late FreighterWallet wallet;

  setUp(() async {
    walletKey = KeyPair.random();
    bridge = ChallengeBridge(walletKey);
    wallet = FreighterWallet(
      bridge,
      challengeCheck: Sep10ChallengeCheck(
        clock: () => challengeNow.add(const Duration(seconds: 30)),
      ),
    );
    await wallet.connect();
  });

  String validChallenge() => buildChallenge(account: walletKey.accountId);

  test(
    'a checked challenge is signed although its source is the server',
    () async {
      final xdr = validChallenge();

      final signed = await wallet.signChallenge(xdr, expectationsFor());

      expect(bridge.signCalls, 1);
      final tx =
          AbstractTransaction.fromEnvelopeXdrString(signed) as Transaction;
      expect(tx.sourceAccount.ed25519AccountId, vectorServerKey.accountId);
      expect(tx.signatures, hasLength(2));
      expect(
        walletKey.verify(
          tx.hash(Network.TESTNET),
          tx.signatures.last.signature.signature,
        ),
        isTrue,
      );
    },
  );

  test('signTransaction still refuses a server-sourced challenge', () async {
    await expectLater(
      wallet.signTransaction(validChallenge()),
      throwsA(isA<WalletInvalidPayload>()),
    );
    expect(bridge.signCalls, 0);
  });

  test('a changed body is rejected', () async {
    bridge.signer = (_) => _signWith(
      walletKey,
      buildChallenge(account: walletKey.accountId, home: 'other.example'),
    );

    await expectLater(
      wallet.signChallenge(validChallenge(), expectationsFor()),
      throwsA(
        isA<WalletInvalidPayload>().having(
          (e) => e.reason,
          'reason',
          contains('changed'),
        ),
      ),
    );
  });

  test('a signature from another account is rejected', () async {
    bridge.signer = (xdr) => _signWith(KeyPair.random(), xdr);

    await expectLater(
      wallet.signChallenge(validChallenge(), expectationsFor()),
      throwsA(
        isA<WalletInvalidPayload>().having(
          (e) => e.reason,
          'reason',
          contains('connected account'),
        ),
      ),
    );
  });

  test('an answer without a new signature is rejected', () async {
    bridge.signer = (xdr) => xdr;

    await expectLater(
      wallet.signChallenge(validChallenge(), expectationsFor()),
      throwsA(isA<WalletInvalidPayload>()),
    );
  });

  test('W39: a failed check never reaches Freighter', () async {
    await expectLater(
      wallet.signChallenge(
        buildChallenge(account: walletKey.accountId, home: 'evil.example'),
        expectationsFor(),
      ),
      throwsA(
        isA<WalletInvalidChallenge>().having(
          (e) => e.rejection,
          'rejection',
          ChallengeRejection.homeDomain,
        ),
      ),
    );
    expect(bridge.signCalls, 0);
  });

  test('a challenge for another account never reaches Freighter', () async {
    await expectLater(
      wallet.signChallenge(
        buildChallenge(account: KeyPair.random().accountId),
        expectationsFor(),
      ),
      throwsA(isA<WalletInvalidChallenge>()),
    );
    expect(bridge.signCalls, 0);
  });

  test(
    'an account switched in Freighter is refused before the prompt',
    () async {
      bridge.activeAddress = KeyPair.random().accountId;

      await expectLater(
        wallet.signChallenge(validChallenge(), expectationsFor()),
        throwsA(isA<WalletAccountChanged>()),
      );
      expect(bridge.signCalls, 0);
    },
  );

  test('without a connection nothing is signed', () async {
    await wallet.disconnect();

    await expectLater(
      wallet.signChallenge(validChallenge(), expectationsFor()),
      throwsA(isA<WalletUnavailable>()),
    );
    expect(bridge.signCalls, 0);
  });
}
