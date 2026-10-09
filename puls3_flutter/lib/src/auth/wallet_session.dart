import 'package:flutter/foundation.dart';
import 'package:puls3_client/puls3_client.dart';

import '../state/wallet_controller.dart';
import '../wallet/sep10/sep10_challenge_check.dart';
import '../wallet/wallet_port.dart';
import 'auth_gateway.dart';

/// The wallet-authenticated server session (design D16, scenarios W41–W44).
///
/// A container that composes the session-agnostic [WalletController] with an
/// [AuthGateway]: connecting signs in with a SEP-10 challenge, [run] keeps
/// protected calls signed in, and [disconnect] signs out. The `wallet`
/// argument must be the port the controller wraps; it signs the challenge.
class WalletSession extends ChangeNotifier {
  WalletSession({
    required this._controller,
    required this._wallet,
    required this._gateway,
    required this._expected,
  }) {
    _gateway.sessionChanges.addListener(_onSessionChanged);
  }

  final WalletController _controller;
  final WalletPort _wallet;
  final AuthGateway _gateway;
  final ChallengeExpectations _expected;

  String? _signedInWallet;
  Future<String>? _signingIn;

  /// The wallet the server session belongs to, or null while signed out.
  String? get wallet => _signedInWallet;

  bool get isSignedIn => _signedInWallet != null && _gateway.isSignedIn;

  /// Connects the wallet and signs in (W41). Concurrent calls share one
  /// challenge.
  Future<String> connect() => _signingIn ??= _signIn().whenComplete(() {
    _signingIn = null;
  });

  /// Runs [action] with a session. Without one it signs in first. When the
  /// action fails with HTTP 401, or the session was dropped (a failed token
  /// refresh), it signs in again with a new challenge and retries once
  /// (W43). Token refresh itself is the gateway's job (W42).
  Future<T> run<T>(Future<T> Function() action) async {
    if (!isSignedIn) await connect();
    try {
      return await action();
    } on Object catch (error) {
      if (!_isUnauthorized(error) && _gateway.isSignedIn) rethrow;
      await connect();
      return action();
    }
  }

  /// Signs this device out on the server, then disconnects the wallet (W44).
  Future<void> disconnect() async {
    try {
      await _gateway.signOutDevice();
    } finally {
      _clear();
      await _controller.disconnect();
    }
  }

  Future<String> _signIn() async {
    final address = await _controller.connect();
    final challenge = await _gateway.createChallenge(address);
    if (challenge.networkPassphrase != _expected.networkPassphrase) {
      throw const WalletInvalidChallenge(ChallengeRejection.network);
    }
    final signed = await _wallet.signChallenge(challenge.payload, _expected);
    await _gateway.signIn(
      challengeId: challenge.challengeId,
      wallet: address,
      signedChallengeXdr: signed,
    );
    _signedInWallet = address;
    notifyListeners();
    return address;
  }

  bool _isUnauthorized(Object error) =>
      error is ServerpodClientHttpException && error.statusCode == 401;

  void _onSessionChanged() {
    if (!_gateway.isSignedIn) _clear();
  }

  void _clear() {
    if (_signedInWallet == null) return;
    _signedInWallet = null;
    notifyListeners();
  }

  @override
  void dispose() {
    _gateway.sessionChanges.removeListener(_onSessionChanged);
    super.dispose();
  }
}
