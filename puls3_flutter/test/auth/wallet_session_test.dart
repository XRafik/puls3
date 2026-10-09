import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:puls3_client/puls3_client.dart';
import 'package:puls3_flutter/src/auth/auth_gateway.dart';
import 'package:puls3_flutter/src/auth/wallet_session.dart';
import 'package:puls3_flutter/src/state/wallet_controller.dart';
import 'package:puls3_flutter/src/wallet/mock_wallet.dart';
import 'package:puls3_flutter/src/wallet/sep10/sep10_challenge_check.dart';
import 'package:puls3_flutter/src/wallet/wallet_port.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

import '../wallet/sep10_fixtures.dart';

/// Plays the server and the Serverpod session manager: issues fixture
/// challenges, verifies the wallet's signature, and holds one session whose
/// access token can expire and whose refresh can fail.
class FakeAuthGateway with ChangeNotifier implements AuthGateway {
  String home = homeDomain;
  String network = 'Test SDF Network ; September 2015';

  int createCalls = 0;
  int signInCalls = 0;
  int signOutCalls = 0;
  int refreshes = 0;

  String? sessionWallet;
  bool accessExpired = false;
  bool refreshValid = true;
  String? lastSignedXdr;

  @override
  bool get isSignedIn => sessionWallet != null;

  @override
  Listenable get sessionChanges => this;

  @override
  Future<WalletChallenge> createChallenge(String wallet) async {
    createCalls++;
    return WalletChallenge(
      challengeId: 'challenge-$createCalls',
      wallet: wallet,
      payload: buildChallenge(account: wallet, home: home),
      networkPassphrase: network,
      expiresAt: challengeNow.add(const Duration(minutes: 15)),
    );
  }

  @override
  Future<void> signIn({
    required String challengeId,
    required String wallet,
    required String signedChallengeXdr,
  }) async {
    signInCalls++;
    lastSignedXdr = signedChallengeXdr;
    final tx =
        AbstractTransaction.fromEnvelopeXdrString(signedChallengeXdr)
            as Transaction;
    final key = KeyPair.fromAccountId(wallet);
    final hash = tx.hash(Network.TESTNET);
    if (!tx.signatures.any((s) => key.verify(hash, s.signature.signature))) {
      throw StateError('no client signature');
    }
    sessionWallet = wallet;
    accessExpired = false;
    refreshValid = true;
    notifyListeners();
  }

  @override
  Future<void> signOutDevice() async {
    signOutCalls++;
    _clear();
  }

  /// A hire call as the Serverpod client makes it: an expired access token
  /// is refreshed first; a failed refresh signs the device out and the call
  /// is HTTP 401.
  Future<String> protectedCall() async {
    if (sessionWallet == null) throw ServerpodClientUnauthorized();
    if (accessExpired) {
      if (!refreshValid) {
        _clear();
        throw ServerpodClientUnauthorized();
      }
      refreshes++;
      accessExpired = false;
    }
    return 'hire for $sessionWallet';
  }

  void _clear() {
    sessionWallet = null;
    notifyListeners();
  }
}

void main() {
  late KeyPair walletKey;
  late MockWallet wallet;
  late WalletController controller;
  late FakeAuthGateway gateway;
  late WalletSession session;

  setUp(() {
    walletKey = KeyPair.random();
    wallet = MockWallet(
      keyPair: walletKey,
      connectDelay: Duration.zero,
      signDelay: Duration.zero,
      challengeCheck: Sep10ChallengeCheck(
        clock: () => challengeNow.add(const Duration(seconds: 30)),
      ),
    );
    controller = WalletController(wallet);
    gateway = FakeAuthGateway();
    session = WalletSession(
      controller: controller,
      wallet: wallet,
      gateway: gateway,
      expected: expectationsFor(),
    );
  });

  tearDown(() {
    session.dispose();
    controller.dispose();
    gateway.dispose();
  });

  group('W41: connect signs in', () {
    test('create, sign, verify, then expose the wallet', () async {
      final address = await session.connect();

      expect(address, walletKey.accountId);
      expect(gateway.createCalls, 1);
      expect(gateway.signInCalls, 1);
      expect(wallet.prompts, 1);
      expect(session.isSignedIn, isTrue);
      expect(session.wallet, walletKey.accountId);
      expect(controller.isConnected, isTrue);
    });

    test('notifies listeners once signed in', () async {
      var notified = 0;
      session.addListener(() => notified++);

      await session.connect();

      expect(notified, greaterThan(0));
    });

    test('W39: an invalid challenge never reaches verifyChallenge', () async {
      gateway.home = 'evil.example';

      await expectLater(
        session.connect(),
        throwsA(isA<WalletInvalidChallenge>()),
      );
      expect(gateway.signInCalls, 0);
      expect(wallet.prompts, 0);
      expect(session.isSignedIn, isFalse);
    });

    test('a challenge announced for another network is refused', () async {
      gateway.network = 'Public Global Stellar Network ; September 2015';

      await expectLater(
        session.connect(),
        throwsA(
          isA<WalletInvalidChallenge>().having(
            (e) => e.rejection,
            'rejection',
            ChallengeRejection.network,
          ),
        ),
      );
      expect(gateway.signInCalls, 0);
      expect(wallet.prompts, 0);
    });

    test('W40: a declined prompt creates no session', () async {
      wallet.rejectSignatures = true;

      await expectLater(
        session.connect(),
        throwsA(isA<WalletSignatureRejected>()),
      );
      expect(gateway.signInCalls, 0);
      expect(session.isSignedIn, isFalse);
      expect(session.wallet, isNull);
    });

    test('concurrent sign-ins share one challenge', () async {
      await Future.wait([session.connect(), session.connect()]);

      expect(gateway.createCalls, 1);
      expect(gateway.signInCalls, 1);
    });
  });

  group('run', () {
    test('signs in first when there is no session', () async {
      final result = await session.run(gateway.protectedCall);

      expect(result, 'hire for ${walletKey.accountId}');
      expect(gateway.createCalls, 1);
    });

    test(
      'W42: an expired access token refreshes without a challenge',
      () async {
        await session.connect();
        gateway.accessExpired = true;

        final result = await session.run(gateway.protectedCall);

        expect(result, 'hire for ${walletKey.accountId}');
        expect(gateway.refreshes, 1);
        expect(gateway.createCalls, 1);
        expect(wallet.prompts, 1);
      },
    );

    test('W43: a failed refresh runs one new challenge and resumes', () async {
      await session.connect();
      gateway
        ..accessExpired = true
        ..refreshValid = false;

      final result = await session.run(gateway.protectedCall);

      expect(result, 'hire for ${walletKey.accountId}');
      expect(gateway.createCalls, 2);
      expect(gateway.signInCalls, 2);
      expect(session.isSignedIn, isTrue);
    });

    test('retries once only: a second 401 reaches the caller', () async {
      await session.connect();
      var calls = 0;

      await expectLater(
        session.run<void>(() async {
          calls++;
          throw ServerpodClientUnauthorized();
        }),
        throwsA(isA<ServerpodClientUnauthorized>()),
      );
      expect(calls, 2);
      expect(gateway.createCalls, 2);
    });

    test('other failures pass through without a new challenge', () async {
      await session.connect();

      await expectLater(
        session.run<void>(() async => throw StateError('boom')),
        throwsA(isA<StateError>()),
      );
      expect(gateway.createCalls, 1);
    });
  });

  test('a signed-out session listenable clears the wallet', () async {
    await session.connect();
    var notified = 0;
    session.addListener(() => notified++);

    await gateway.signOutDevice();

    expect(session.isSignedIn, isFalse);
    expect(session.wallet, isNull);
    expect(notified, greaterThan(0));
  });

  test('W44: disconnect signs out and disconnects the wallet', () async {
    await session.connect();

    await session.disconnect();

    expect(gateway.signOutCalls, 1);
    expect(gateway.isSignedIn, isFalse);
    expect(session.isSignedIn, isFalse);
    expect(session.wallet, isNull);
    expect(controller.status, WalletStatus.disconnected);
  });

  test('WalletController knows nothing about sessions', () {
    final source = File(
      'lib/src/state/wallet_controller.dart',
    ).readAsStringSync();

    expect(source, isNot(contains('AuthGateway')));
    expect(source, isNot(contains('WalletSession')));
    expect(source, isNot(contains('signChallenge')));
  });
}
