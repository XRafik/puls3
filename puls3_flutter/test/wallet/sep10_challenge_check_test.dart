import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:puls3_flutter/src/wallet/mock_wallet.dart';
import 'package:puls3_flutter/src/wallet/sep10/sep10_challenge_check.dart';
import 'package:puls3_flutter/src/wallet/wallet_port.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

import 'sep10_fixtures.dart';

void main() {
  group('server vector (cross-implementation interop)', () {
    test('passes WebAuth.validateChallenge and the app check', () {
      final vector = readSep10Vector();
      expect(vectorServerKey.accountId, vector['serverAccount']);
      final now = DateTime.parse(vector['now'] as String);
      final expected = ChallengeExpectations(
        serverSigningKey: vector['serverAccount'] as String,
        homeDomain: vector['homeDomain'] as String,
        webAuthDomain: vector['webAuthDomain'] as String,
        networkPassphrase: vector['networkPassphrase'] as String,
      );

      final tx =
          Sep10ChallengeCheck(
            clock: () => now.add(const Duration(minutes: 1)),
          ).validate(
            vector['envelopeXdr'] as String,
            expected: expected,
            account: vector['wallet'] as String,
            walletNetwork: vector['networkPassphrase'] as String,
          );

      expect(
        Util.bytesToHex(tx.hash(Network.TESTNET)),
        vector['transactionHash'],
      );
    });

    test('the same vector fails once the clock passes its time bounds', () {
      final vector = readSep10Vector();
      final now = DateTime.parse(vector['now'] as String);
      expect(
        () =>
            Sep10ChallengeCheck(
              clock: () => now.add(const Duration(minutes: 16)),
            ).validate(
              vector['envelopeXdr'] as String,
              expected: expectationsFor(),
              account: vector['wallet'] as String,
              walletNetwork: vector['networkPassphrase'] as String,
            ),
        throwsA(rejection(ChallengeRejection.timeBounds)),
      );
    });
  });

  group('MockWallet.signChallenge', () {
    late KeyPair walletKey;
    late MockWallet wallet;

    setUp(() async {
      walletKey = KeyPair.random();
      wallet = MockWallet(
        keyPair: walletKey,
        connectDelay: Duration.zero,
        signDelay: Duration.zero,
        challengeCheck: Sep10ChallengeCheck(
          clock: () => challengeNow.add(const Duration(seconds: 30)),
        ),
      );
      await wallet.connect();
    });

    test(
      'W38: a valid challenge prompts once and is signed by the key',
      () async {
        final xdr = buildChallenge(account: walletKey.accountId);

        final signed = await wallet.signChallenge(xdr, expectationsFor());

        expect(wallet.prompts, 1);
        final tx =
            AbstractTransaction.fromEnvelopeXdrString(signed) as Transaction;
        expect(tx.signatures, hasLength(2));
        final hash = tx.hash(Network.TESTNET);
        expect(
          walletKey.verify(hash, tx.signatures.last.signature.signature),
          isTrue,
        );
      },
    );

    test('W40: a declined prompt is WalletSignatureRejected', () async {
      wallet.rejectSignatures = true;
      final xdr = buildChallenge(account: walletKey.accountId);

      await expectLater(
        wallet.signChallenge(xdr, expectationsFor()),
        throwsA(isA<WalletSignatureRejected>()),
      );
      expect(wallet.prompts, 1);
    });

    group('W39: rejected without a prompt', () {
      Future<void> expectRejected(
        String xdr,
        Matcher matcher, {
        ChallengeExpectations? expected,
      }) async {
        await expectLater(
          wallet.signChallenge(xdr, expected ?? expectationsFor()),
          throwsA(matcher),
        );
        expect(wallet.prompts, 0);
      }

      test('wallet on another network', () async {
        wallet.walletNetwork = 'Public Global Stellar Network ; September 2015';
        await expectRejected(
          buildChallenge(account: walletKey.accountId),
          isA<WalletWrongNetwork>(),
        );
      });

      test('challenge signed for another network', () async {
        await expectRejected(
          buildChallenge(account: walletKey.accountId, network: Network.PUBLIC),
          rejection(ChallengeRejection.serverSignature),
        );
      });

      test('wrong home domain', () async {
        await expectRejected(
          buildChallenge(account: walletKey.accountId, home: 'evil.example'),
          rejection(ChallengeRejection.homeDomain),
        );
      });

      test('wrong web auth domain', () async {
        await expectRejected(
          buildChallenge(account: walletKey.accountId, web: 'evil.example'),
          rejection(ChallengeRejection.webAuthDomain),
        );
      });

      test('missing web_auth_domain operation', () async {
        await expectRejected(
          buildChallenge(
            account: walletKey.accountId,
            includeWebAuthDomain: false,
          ),
          rejection(ChallengeRejection.webAuthDomain),
        );
      });

      test('wrong server key', () async {
        final other = KeyPair.random();
        await expectRejected(
          buildChallenge(account: walletKey.accountId, server: other),
          isA<WalletInvalidChallenge>(),
        );
      });

      test('transaction source is not the server key', () async {
        await expectRejected(
          buildChallenge(
            account: walletKey.accountId,
            transactionSource: walletKey.accountId,
          ),
          rejection(ChallengeRejection.source),
        );
      });

      test('first operation for another account', () async {
        await expectRejected(
          buildChallenge(account: KeyPair.random().accountId),
          rejection(ChallengeRejection.operationSource),
        );
      });

      test('extra operation that is not manage_data', () async {
        await expectRejected(
          buildChallenge(
            account: walletKey.accountId,
            extra: [
              BumpSequenceOperationBuilder(
                BigInt.one,
              ).setSourceAccount(vectorServerKey.accountId).build(),
            ],
          ),
          rejection(ChallengeRejection.operationType),
        );
      });

      test('foreign-sourced extra manage_data operation', () async {
        await expectRejected(
          buildChallenge(
            account: walletKey.accountId,
            extra: [
              ManageDataOperationBuilder(
                'extra',
                null,
              ).setSourceAccount(KeyPair.random().accountId).build(),
            ],
          ),
          rejection(ChallengeRejection.operationSource),
        );
      });

      test('non-zero sequence', () async {
        await expectRejected(
          buildChallenge(account: walletKey.accountId, sequence: 7),
          rejection(ChallengeRejection.sequence),
        );
      });

      test('missing time bounds', () async {
        await expectRejected(
          buildChallenge(account: walletKey.accountId, timeBounds: false),
          rejection(ChallengeRejection.timeBounds),
        );
      });

      test('expired time bounds', () async {
        await expectRejected(
          buildChallenge(
            account: walletKey.accountId,
            now: challengeNow.subtract(const Duration(minutes: 20)),
          ),
          rejection(ChallengeRejection.timeBounds),
        );
      });

      test('bad server signature', () async {
        await expectRejected(
          buildChallenge(
            account: walletKey.accountId,
            signer: KeyPair.random(),
          ),
          rejection(ChallengeRejection.serverSignature),
        );
      });

      test('malformed XDR', () async {
        await expectRejected(
          'not-xdr',
          rejection(ChallengeRejection.malformed),
        );
      });

      test('trailing bytes after a valid envelope', () async {
        final xdr = buildChallenge(account: walletKey.accountId);
        await expectRejected(
          base64Encode([...base64Decode(xdr), 0, 0, 0, 0]),
          rejection(ChallengeRejection.malformed),
        );
      });

      test('expectations for another server', () async {
        await expectRejected(
          buildChallenge(account: walletKey.accountId),
          isA<WalletInvalidChallenge>(),
          expected: expectationsFor(server: KeyPair.random()),
        );
      });
    });
  });
}

Matcher rejection(ChallengeRejection reason) => isA<WalletInvalidChallenge>()
    .having((e) => e.rejection, 'rejection', reason);
