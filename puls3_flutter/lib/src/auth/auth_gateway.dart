import 'package:flutter/foundation.dart';
import 'package:puls3_client/puls3_client.dart';
import 'package:serverpod_auth_idp_flutter/serverpod_auth_idp_flutter.dart';

/// The server side of a wallet sign-in, as [WalletSession] needs it
/// (design D16). Tests use a fake; the app uses [ServerpodAuthGateway].
abstract interface class AuthGateway {
  /// A single-use SEP-10 challenge for [wallet] (`walletAuth.createChallenge`).
  Future<WalletChallenge> createChallenge(String wallet);

  /// Verifies the signed challenge and stores the session it returns, so
  /// later calls carry its token.
  Future<void> signIn({
    required String challengeId,
    required String wallet,
    required String signedChallengeXdr,
  });

  /// Revokes this device's session on the server and forgets it locally.
  Future<void> signOutDevice();

  /// Whether a session is stored.
  bool get isSignedIn;

  /// Fires when the stored session changes, including a sign-out after a
  /// failed token refresh.
  Listenable get sessionChanges;
}

/// [AuthGateway] over the generated client and Serverpod's session manager.
///
/// The client must have a [FlutterAuthSessionManager] as its
/// `authSessionManager`. Expired access tokens are refreshed by that manager;
/// when the refresh fails it signs out and [sessionChanges] fires.
final class ServerpodAuthGateway implements AuthGateway {
  ServerpodAuthGateway(this._client);

  final Client _client;

  @override
  Future<WalletChallenge> createChallenge(String wallet) =>
      _client.walletAuth.createChallenge(wallet);

  @override
  Future<void> signIn({
    required String challengeId,
    required String wallet,
    required String signedChallengeXdr,
  }) async {
    final auth = await _client.walletAuth.verifyChallenge(
      challengeId,
      wallet,
      signedChallengeXdr,
    );
    await _client.auth.updateSignedInUser(auth);
  }

  @override
  Future<void> signOutDevice() => _client.auth.signOutDevice();

  @override
  bool get isSignedIn => _client.auth.isAuthenticated;

  @override
  Listenable get sessionChanges =>
      _client.authSessionManager.authInfoListenable;
}
