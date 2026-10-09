import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

import 'sep10/sep10_challenge_check.dart';
import 'wallet_port.dart';

/// Fake wallet for tests and the demo console (#32). It never touches a
/// network. Its transaction and auth-entry "signatures" are placeholders a
/// real server would reject; SEP-10 challenges are signed with a real
/// test key, [keyPair], so a server can verify the sign-in.
class MockWallet implements WalletPort {
  MockWallet({
    KeyPair? keyPair,
    this.connectDelay = const Duration(milliseconds: 500),
    this.signDelay = const Duration(milliseconds: 1200),
    this.challengeCheck = const Sep10ChallengeCheck(),
  }) : _keyPair = keyPair ?? KeyPair.random();

  /// Prefix of every payload this wallet "signs".
  static const signedPrefix = 'mock-signed:';

  /// The test key of the simulated account. Never a real user's key.
  KeyPair _keyPair;
  final Sep10ChallengeCheck challengeCheck;
  final Duration connectDelay;
  final Duration signDelay;

  @override
  String get name => 'Demo wallet';

  @override
  Uri? get installUrl => null;

  /// The network the simulated wallet is on. Set it to the public network
  /// passphrase to reproduce the wrong-network error.
  String walletNetwork = stellarTestnetPassphrase;

  /// While true, connection requests are declined, as if the user pressed
  /// "Reject" in the wallet's connect prompt.
  bool rejectConnection = false;

  /// While true, every signature request is declined with
  /// [WalletSignatureRejected].
  bool rejectSignatures = false;

  /// When set, connection and signature requests fail with it, for example
  /// [WalletNotInstalled], [WalletUnavailable] or [WalletWrongNetwork].
  WalletException? failure;

  /// How many signing prompts the simulated wallet has shown.
  int prompts = 0;

  /// The account inside the simulated wallet; it survives a disconnect,
  /// as in a real wallet.
  String? _account;
  String? _address;

  @override
  String? get address => _address;

  @override
  String? get network => _address == null ? null : walletNetwork;

  @override
  Future<void> disconnect() async => _address = null;

  /// Simulates the user switching to another account in the wallet.
  void switchAccount() {
    _keyPair = KeyPair.random();
    _address = _account = _keyPair.accountId;
  }

  @override
  Future<String> connect() async {
    await Future<void>.delayed(connectDelay);
    final failure = this.failure;
    if (failure != null) throw failure;
    if (rejectConnection) throw const WalletSignatureRejected();
    if (walletNetwork != stellarTestnetPassphrase) {
      throw const WalletWrongNetwork();
    }
    return _address = _account ??= _keyPair.accountId;
  }

  /// Returns [unsignedXdr] marked as signed: a stand-in for the signed
  /// envelope a real wallet returns, not a valid Stellar signature.
  @override
  Future<String> signTransaction(String unsignedXdr) => _sign(unsignedXdr);

  @override
  Future<String> signAuthEntry(String entryXdr) => _sign(entryXdr);

  /// Checks the challenge first, then signs it with [keyPair] for real.
  @override
  Future<String> signChallenge(
    String challengeXdr,
    ChallengeExpectations expected,
  ) async {
    final account = _address ?? await connect();
    final challenge = challengeCheck.validate(
      challengeXdr,
      expected: expected,
      account: account,
      walletNetwork: walletNetwork,
    );
    await _prompt();
    challenge.sign(_keyPair, Network(expected.networkPassphrase));
    return challenge.toEnvelopeXdrBase64();
  }

  Future<String> _sign(String payload) async {
    if (_address == null) await connect();
    await _prompt();
    if (walletNetwork != stellarTestnetPassphrase) {
      throw const WalletWrongNetwork();
    }
    return '$signedPrefix$payload';
  }

  /// The simulated signing prompt: counted, then declined or failed when
  /// the test asks for it.
  Future<void> _prompt() async {
    prompts++;
    await Future<void>.delayed(signDelay);
    final failure = this.failure;
    if (failure != null) throw failure;
    if (rejectSignatures) throw const WalletSignatureRejected();
  }
}
