import 'dart:convert';

import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

/// Build-time overrides for the SEP-10 values (`--dart-define=<name>=<value>`).
/// A blank value means "use `assets/config.json`".
const Map<String, String> authConfigDefines = {
  AuthConfig.serverSigningKeyDefine: String.fromEnvironment(
    AuthConfig.serverSigningKeyDefine,
  ),
  AuthConfig.homeDomainDefine: String.fromEnvironment(
    AuthConfig.homeDomainDefine,
  ),
  AuthConfig.webAuthDomainDefine: String.fromEnvironment(
    AuthConfig.webAuthDomainDefine,
  ),
  AuthConfig.networkPassphraseDefine: String.fromEnvironment(
    AuthConfig.networkPassphraseDefine,
  ),
};

/// What the app expects of every SEP-10 challenge (design D11).
///
/// The values come from the `auth` block of `config.json`: the web build gets
/// it from the server's `AppConfigRoute` (same TLS origin), native builds
/// bundle it and can override each field with a dart-define. A challenge
/// response never vouches for its own signer, so the server key is pinned
/// here. [serverSigningKey] is a public `G…` address; a secret is refused.
final class AuthConfig {
  const AuthConfig({
    required this.serverSigningKey,
    required this.homeDomain,
    required this.webAuthDomain,
    required this.networkPassphrase,
  });

  static const serverSigningKeyDefine = 'PULS3_AUTH_SERVER_SIGNING_KEY';
  static const homeDomainDefine = 'PULS3_AUTH_HOME_DOMAIN';
  static const webAuthDomainDefine = 'PULS3_AUTH_WEB_AUTH_DOMAIN';
  static const networkPassphraseDefine = 'PULS3_AUTH_NETWORK_PASSPHRASE';

  /// Parses the `auth` block of [configJson]. A non-blank entry of
  /// [overrides] (keyed by the define names) wins over the file.
  ///
  /// Throws [AuthConfigUnavailable] when a value is missing or the server
  /// key is not a Stellar account address: sign-in fails closed.
  factory AuthConfig.parse(
    String configJson, {
    Map<String, String> overrides = authConfigDefines,
  }) {
    final config = jsonDecode(configJson);
    final auth = config is Map<String, dynamic> ? config['auth'] : null;
    final block = auth is Map<String, dynamic> ? auth : const {};
    final missing = <String>[];

    String read(String field, String define) {
      final override = overrides[define]?.trim() ?? '';
      if (override.isNotEmpty) return override;
      final value = block[field];
      if (value is String && value.trim().isNotEmpty) return value.trim();
      missing.add(field);
      return '';
    }

    final parsed = AuthConfig(
      serverSigningKey: read('serverSigningKey', serverSigningKeyDefine),
      homeDomain: read('homeDomain', homeDomainDefine),
      webAuthDomain: read('webAuthDomain', webAuthDomainDefine),
      networkPassphrase: read('networkPassphrase', networkPassphraseDefine),
    );
    if (missing.isNotEmpty) throw AuthConfigUnavailable(missing);
    if (!parsed.serverSigningKey.startsWith('G') ||
        !StrKey.isValidStellarAccountId(parsed.serverSigningKey)) {
      // The value is never echoed: it might be a secret seed.
      throw const AuthConfigUnavailable(
        ['serverSigningKey'],
        reason: 'must be a public Stellar account address (G…)',
      );
    }
    return parsed;
  }

  /// The server's public signing account (`G…`).
  final String serverSigningKey;

  /// Expected in the first operation's name, `<homeDomain> auth`.
  final String homeDomain;

  /// Expected as the value of the `web_auth_domain` operation.
  final String webAuthDomain;

  /// The network every challenge and the wallet must be on.
  final String networkPassphrase;
}

/// The SEP-10 config is incomplete or invalid, so the app cannot check a
/// challenge and does not sign in.
final class AuthConfigUnavailable implements Exception {
  const AuthConfigUnavailable(this.missing, {this.reason = 'is missing'});

  /// The `auth` fields that are missing or invalid.
  final List<String> missing;

  /// Why, without the offending value.
  final String reason;

  @override
  String toString() =>
      'AuthConfigUnavailable: auth.${missing.join(', auth.')} $reason. Set '
      'it in assets/config.json or with --dart-define.';
}
