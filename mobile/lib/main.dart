import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'core/app_config.dart';
import 'core/app_theme.dart';
import 'providers/app_state.dart';
import 'repositories/agenttrust_repository.dart';
import 'screens/auth_screens.dart';
import 'screens/home_shell.dart';
import 'screens/splash_screen.dart';
import 'services/api_client.dart';
import 'services/token_store.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final api = HttpAgentTrustApi(AppConfig.apiBaseUrl);
  runApp(
    AgentTrustApp(
      state: AppState(AgentTrustRepository(api, SecureTokenStore()))
        ..initialize(),
    ),
  );
}

class AgentTrustApp extends StatelessWidget {
  const AgentTrustApp({required this.state, super.key});
  final AppState state;
  @override
  Widget build(BuildContext context) => ChangeNotifierProvider.value(
    value: state,
    child: MaterialApp(
      title: 'AgentTrust',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light,
      home: Consumer<AppState>(
        builder: (context, state, child) => switch (state.authState) {
          AuthState.checking => const SplashScreen(),
          AuthState.signedOut => const LoginScreen(),
          AuthState.mfaRequired => const MfaScreen(),
          AuthState.signedIn => const HomeShell(),
        },
      ),
    ),
  );
}
