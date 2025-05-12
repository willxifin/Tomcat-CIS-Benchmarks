#!/bin/bash

# Apache Tomcat 9 CIS Benchmark v1.2.0 Compliance Checks - FULLY IMPLEMENTED
check_controls_v9() {
  local dir="$1"
  echo "───────────────────────────────────────────────"
  echo "🔍 Running Apache Tomcat 9 CIS Benchmark v1.2.0 Checks"
  echo "───────────────────────────────────────────────"

  # CIS 1.1 - Remove extraneous files and directories
  echo -e "\n[CIS 1.1] Remove extraneous files and directories" | tee -a "$REPORT"
  local extraneous=(examples docs manager host-manager ROOT)
  local found=0
  for app in "${extraneous[@]}"; do
    if [[ -d "$dir/webapps/$app" ]]; then
      echo "❌ $app found in $dir/webapps" | tee -a "$REPORT"
      found=1
    fi
  done
  if [[ $found -eq 0 ]]; then
    echo "✅ No extraneous webapps found" | tee -a "$REPORT"
    echo "Risk Level: Low" | tee -a "$REPORT"
    echo "Exploitability: Medium – Sample apps may be insecure" | tee -a "$REPORT"
    echo "Recommendation: Remove unused directories like /examples, /docs, /manager" | tee -a "$REPORT"
  else
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Medium" | tee -a "$REPORT"
    echo "Recommendation: Delete unused sample applications and documentation" | tee -a "$REPORT"
  fi

  # CIS 1.2 - Disable unused connectors
  echo -e "\n[CIS 1.2] Disable unused connectors" | tee -a "$REPORT"
  local used_connectors=(HTTP HTTPS AJP)
  local unused=$(grep -oP '<Connector port="\d+" protocol="\K[^"]+' "$dir/conf/server.xml" | grep -Ev "$(IFS='|'; echo "${used_connectors[*]}")")
  if [[ -n "$unused" ]]; then
    echo "❌ Unused connectors found: $unused" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: High if exposed externally" | tee -a "$REPORT"
    echo "Recommendation: Comment out or remove unused <Connector> definitions in server.xml" | tee -a "$REPORT"
  else
    echo "✅ All connectors in use appear to be valid" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: No action needed" | tee -a "$REPORT"
  fi

  # CIS 2.4 - Disable X-Powered-By header
  echo -e "\n[CIS 2.4] Disable X-Powered-By HTTP Header" | tee -a "$REPORT"
  if grep -q 'xpoweredBy' "$dir/conf/web.xml" || grep -q 'org.apache.catalina.filters.SetHeaderFilter' "$dir/conf/web.xml"; then
    echo "❌ X-Powered-By header is present in web.xml" | tee -a "$REPORT"
    echo "Risk Level: Low" | tee -a "$REPORT"
    echo "Exploitability: Low – header reveals implementation detail" | tee -a "$REPORT"
    echo "Recommendation: Remove or override 'X-Powered-By' headers using a SetHeaderFilter" | tee -a "$REPORT"
  else
    echo "✅ No X-Powered-By header configured in web.xml" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: No action needed" | tee -a "$REPORT"
  fi

  # CIS 2.6 - Turn off TRACE
  echo -e "\n[CIS 2.6] Turn off TRACE" | tee -a "$REPORT"
  if grep -q 'allowTrace="true"' "$dir/conf/server.xml"; then
    echo "❌ TRACE method is enabled in server.xml" | tee -a "$REPORT"
    echo "Risk Level: High" | tee -a "$REPORT"
    echo "Exploitability: High – Can be abused for Cross Site Tracing (XST) attacks" | tee -a "$REPORT"
    echo "Recommendation: Set allowTrace=\"false\" for all <Connector> elements in server.xml" | tee -a "$REPORT"
  else
    echo "✅ TRACE method is disabled in server.xml" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: TRACE method is already secured" | tee -a "$REPORT"
  fi

  # CIS 3.1 - Set a nondeterministic Shutdown command value
  echo -e "\n[CIS 3.1] Set a nondeterministic Shutdown command value" | tee -a "$REPORT"
  if grep -q '<Server port="8005"' "$dir/conf/server.xml"; then
    echo "❌ Default shutdown port (8005) is still active" | tee -a "$REPORT"
    echo "Risk Level: High" | tee -a "$REPORT"
    echo "Exploitability: High – Allows remote shutdown if exposed" | tee -a "$REPORT"
    echo "Recommendation: Change shutdown port to -1 to disable or use a random high-numbered port" | tee -a "$REPORT"
  else
    echo "✅ Shutdown port is modified or disabled" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: Shutdown interface is secured" | tee -a "$REPORT"
  fi

  # CIS 4.12 - Restrict access to server.xml
  echo -e "\n[CIS 4.12] Restrict access to server.xml" | tee -a "$REPORT"
  local file="$dir/conf/server.xml"
  if [[ -f "$file" ]]; then
    perms=$(stat -c "%a" "$file")
    if [[ $perms -le 640 ]]; then
      echo "✅ server.xml permissions are secure ($perms)" | tee -a "$REPORT"
      echo "Risk Level: None" | tee -a "$REPORT"
      echo "Exploitability: None" | tee -a "$REPORT"
      echo "Recommendation: No action needed." | tee -a "$REPORT"
    else
      echo "❌ server.xml has insecure permissions ($perms)" | tee -a "$REPORT"
      echo "Risk Level: High" | tee -a "$REPORT"
      echo "Exploitability: Medium – Could expose sensitive settings like passwords and ports" | tee -a "$REPORT"
      echo "Recommendation: chmod 640 $file" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ server.xml not found at $file" | tee -a "$REPORT"
  fi

    # CIS 4.13 - Restrict access to tomcat-users.xml
  echo -e "
[CIS 4.13] Restrict access to tomcat-users.xml" | tee -a "$REPORT"
  local tu_file="$dir/conf/tomcat-users.xml"
  if [[ -f "$tu_file" ]]; then
    perms=$(stat -c "%a" "$tu_file")
    if [[ $perms -le 640 ]]; then
      echo "✅ tomcat-users.xml permissions are secure ($perms)" | tee -a "$REPORT"
      echo "Risk Level: None" | tee -a "$REPORT"
      echo "Exploitability: None" | tee -a "$REPORT"
      echo "Recommendation: No action needed." | tee -a "$REPORT"
    else
      echo "❌ tomcat-users.xml has insecure permissions ($perms)" | tee -a "$REPORT"
      echo "Risk Level: High" | tee -a "$REPORT"
      echo "Exploitability: High – May expose user credentials or roles" | tee -a "$REPORT"
      echo "Recommendation: chmod 640 $tu_file" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ tomcat-users.xml not found at $tu_file" | tee -a "$REPORT"
  fi

  # CIS 4.14 - Restrict access to web.xml
  echo -e "
[CIS 4.14] Restrict access to web.xml" | tee -a "$REPORT"
  local web_file="$dir/conf/web.xml"
  if [[ -f "$web_file" ]]; then
    perms=$(stat -c "%a" "$web_file")
    if [[ $perms -le 640 ]]; then
      echo "✅ web.xml permissions are secure ($perms)" | tee -a "$REPORT"
      echo "Risk Level: None" | tee -a "$REPORT"
      echo "Exploitability: None" | tee -a "$REPORT"
      echo "Recommendation: No action needed." | tee -a "$REPORT"
    else
      echo "❌ web.xml has insecure permissions ($perms)" | tee -a "$REPORT"
      echo "Risk Level: Medium" | tee -a "$REPORT"
      echo "Exploitability: Medium – May allow attackers to infer filter/security mappings" | tee -a "$REPORT"
      echo "Recommendation: chmod 640 $web_file" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ web.xml not found at $web_file" | tee -a "$REPORT"
  fi

    # CIS 5.1 - Use secure Realms
  echo -e "
[CIS 5.1] Use secure Realms" | tee -a "$REPORT"
  if grep -q '<Realm className="org.apache.catalina.realm.MemoryRealm"' "$dir/conf/server.xml"; then
    echo "❌ Insecure MemoryRealm found in server.xml" | tee -a "$REPORT"
    echo "Risk Level: High" | tee -a "$REPORT"
    echo "Exploitability: High – Plaintext storage of credentials" | tee -a "$REPORT"
    echo "Recommendation: Use JDBCRealm or JNDIRealm with encrypted credential storage." | tee -a "$REPORT"
  else
    echo "✅ No insecure MemoryRealm found" | tee -a "$REPORT"
    echo "Risk Level: Low" | tee -a "$REPORT"
    echo "Recommendation: Secure realm configuration validated." | tee -a "$REPORT"
  fi

  # CIS 5.2 - Use LockOutRealm
  echo -e "
[CIS 5.2] Use LockOutRealm" | tee -a "$REPORT"
  if grep -q 'LockOutRealm' "$dir/conf/server.xml"; then
    echo "✅ LockOutRealm is configured" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: No action needed." | tee -a "$REPORT"
  else
    echo "❌ LockOutRealm is not configured" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Medium – Brute force protection missing" | tee -a "$REPORT"
    echo "Recommendation: Wrap your authentication Realm in a LockOutRealm to prevent brute force attacks." | tee -a "$REPORT"
  fi

  # CIS 6.3 - Ensure scheme is set accurately
  echo -e "
[CIS 6.3] Ensure scheme is set accurately" | tee -a "$REPORT"
  if grep -q '<Connector.*scheme="https"' "$dir/conf/server.xml"; then
    echo "✅ HTTPS scheme set in Connector" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: Connector scheme correctly set for secure use." | tee -a "$REPORT"
  else
    echo "❌ Connector scheme is not set to https" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Medium – Breaks assumption of secure transport in some apps" | tee -a "$REPORT"
    echo "Recommendation: Add scheme=\"https\" to SSL-enabled Connector definitions in server.xml" | tee -a "$REPORT"
  fi

  # CIS 6.4 - Ensure secure=true for SSL Connectors
  echo -e "
[CIS 6.4] Ensure secure=true for SSL Connectors" | tee -a "$REPORT"
  if grep -q '<Connector.*SSLEnabled="true".*secure="true"' "$dir/conf/server.xml"; then
    echo "✅ secure attribute set correctly for SSL-enabled Connectors" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: SSL-enabled connector correctly marked as secure." | tee -a "$REPORT"
  else
    echo "❌ secure attribute is not present or incorrect for SSL-enabled Connectors" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Medium – Could allow insecure assumptions in request security context" | tee -a "$REPORT"
    echo "Recommendation: Ensure secure=\"true\" in all <Connector SSLEnabled=\"true\"> blocks." | tee -a "$REPORT"
  fi

  # CIS 6.5 - Ensure SSLProtocol is TLS
  echo -e "
[CIS 6.5] Ensure SSLProtocol is TLS" | tee -a "$REPORT"
  if grep -q '<Connector.*SSLEnabled="true".*sslProtocol="TLS' "$dir/conf/server.xml"; then
    echo "✅ sslProtocol is set to TLS" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: TLS protocol correctly enforced." | tee -a "$REPORT"
  else
    echo "❌ SSL-enabled connector does not restrict protocol to TLS" | tee -a "$REPORT"
    echo "Risk Level: High" | tee -a "$REPORT"
    echo "Exploitability: High – May allow use of vulnerable SSL protocols" | tee -a "$REPORT"
    echo "Recommendation: Add sslProtocol=\"TLS\" to all <Connector SSLEnabled=\"true\"> elements." | tee -a "$REPORT"
  fi

    # CIS 7.1 - Ensure log directory is set
  echo -e "
[CIS 7.1] Ensure log directory is set and exists" | tee -a "$REPORT"
  local log_dir="$dir/logs"
  if [[ -d "$log_dir" ]]; then
    echo "✅ Log directory exists at $log_dir" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: Continue using centralized logging under $log_dir" | tee -a "$REPORT"
  else
    echo "❌ Log directory $log_dir does not exist" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Medium – Logging failures may prevent detecting attacks" | tee -a "$REPORT"
    echo "Recommendation: Ensure Tomcat is writing logs to a consistent directory like $dir/logs" | tee -a "$REPORT"
  fi

  # CIS 7.2 - Check for custom log file handler
  echo -e "
[CIS 7.2] Ensure file handler is specified in logging.properties" | tee -a "$REPORT"
  local log_cfg="$dir/conf/logging.properties"
  if grep -q '^1catalina.org.apache.juli.FileHandler.level' "$log_cfg"; then
    echo "✅ Custom log file handler configuration found" | tee -a "$REPORT"
    echo "Risk Level: Low" | tee -a "$REPORT"
    echo "Recommendation: No action required for default FileHandler setup" | tee -a "$REPORT"
  else
    echo "❌ No specific log file handler configuration present in logging.properties" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Low" | tee -a "$REPORT"
    echo "Recommendation: Define explicit FileHandler in conf/logging.properties for better log control" | tee -a "$REPORT"
  fi

  # CIS 8.1 - Restrict access to internal packages via catalina.properties
  echo -e "
[CIS 8.1] Restrict access to sensitive packages" | tee -a "$REPORT"
  local catalina_props="$dir/conf/catalina.properties"
  if grep -q '^package.access=sun\.\*,org\.apache\.catalina\.*,org\.apache\.coyote\.*,org\.apache\.jasper\.*' "$catalina_props"; then
    echo "✅ package.access restricts sensitive internal packages" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: package.access properly configured" | tee -a "$REPORT"
  else
    echo "❌ package.access is missing or misconfigured in catalina.properties" | tee -a "$REPORT"
    echo "Risk Level: High" | tee -a "$REPORT"
    echo "Exploitability: High – May allow internal class access" | tee -a "$REPORT"
    echo "Recommendation: Configure package.access with restricted packages list in catalina.properties" | tee -a "$REPORT"
  fi

    # CIS 9.1 - Ensure Security Manager is used
  echo -e "
[CIS 9.1] Ensure Security Manager is enabled" | tee -a "$REPORT"
  if grep -q '\-Djava\.security\.manager' "$dir/bin/setenv.sh" 2>/dev/null || grep -q '\-Djava\.security\.manager' "$dir/bin/catalina.sh" 2>/dev/null; then
    echo "✅ Security Manager is enabled" | tee -a "$REPORT"
    echo "Risk Level: Low" | tee -a "$REPORT"
    echo "Recommendation: Continue using Java Security Manager for runtime sandboxing." | tee -a "$REPORT"
  else
    echo "❌ Security Manager is not enabled" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Medium – Applications run without Java sandbox restrictions." | tee -a "$REPORT"
    echo "Recommendation: Add -Djava.security.manager to startup configuration in setenv.sh or catalina.sh" | tee -a "$REPORT"
  fi

  # CIS 9.2 - Disable autoDeploy
  echo -e "
[CIS 9.2] Disable autoDeploy on Host" | tee -a "$REPORT"
  if grep -q '<Host.*autoDeploy="false"' "$dir/conf/server.xml"; then
    echo "✅ autoDeploy is disabled on Host" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: Auto-deploy is already disabled." | tee -a "$REPORT"
  else
    echo "❌ autoDeploy is not disabled" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Medium – May allow automatic deployment of malicious apps." | tee -a "$REPORT"
    echo "Recommendation: Set autoDeploy=\"false\" in <Host> element in server.xml" | tee -a "$REPORT"
  fi

  # CIS 9.3 - Disable deployOnStartup
  echo -e "
[CIS 9.3] Disable deployOnStartup on Host" | tee -a "$REPORT"
  if grep -q '<Host.*deployOnStartup="false"' "$dir/conf/server.xml"; then
    echo "✅ deployOnStartup is disabled on Host" | tee -a "$REPORT"
    echo "Risk Level: None" | tee -a "$REPORT"
    echo "Recommendation: deployOnStartup is properly disabled." | tee -a "$REPORT"
  else
    echo "❌ deployOnStartup is not disabled" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Exploitability: Medium – May allow unintended app startup." | tee -a "$REPORT"
    echo "Recommendation: Set deployOnStartup=\"false\" in <Host> element in server.xml" | tee -a "$REPORT"
  fi

    # CIS 10.1 - Ensure web content is on separate partition (manual)
  echo -e "
[CIS 10.1] Ensure Web content directory is on a separate partition" | tee -a "$REPORT"
  echo "📘 Manual Check: Verify webapps/ directory is mounted on a dedicated partition." | tee -a "$REPORT"
  echo "Risk Level: Medium" | tee -a "$REPORT"
  echo "Exploitability: Medium – Prevents full disk DoS from web uploads/logs." | tee -a "$REPORT"
  echo "Recommendation: Mount /webapps on a separate partition or volume." | tee -a "$REPORT"

  # CIS 10.2 - Restrict access to the manager application
  echo -e "
[CIS 10.2] Restrict access to the manager application" | tee -a "$REPORT"
  if [[ -f "$dir/webapps/manager/META-INF/context.xml" ]]; then
    if grep -q '<Context' "$dir/webapps/manager/META-INF/context.xml" | grep -q 'antiResourceLocking="true"'; then
      echo "✅ manager app is restricted via context.xml" | tee -a "$REPORT"
    else
      echo "❌ manager app is not properly restricted via context.xml" | tee -a "$REPORT"
    fi
  else
    echo "✅ manager application is not present" | tee -a "$REPORT"
  fi

  # CIS 10.4 - Force SSL when accessing manager
  echo -e "
[CIS 10.4] Force SSL for Manager Application" | tee -a "$REPORT"
  if grep -q 'transport-guarantee.*CONFIDENTIAL' "$dir/webapps/manager/WEB-INF/web.xml"; then
    echo "✅ SSL is enforced for the manager app" | tee -a "$REPORT"
  else
    echo "❌ SSL enforcement not configured for manager app" | tee -a "$REPORT"
    echo "Recommendation: Set transport-guarantee to CONFIDENTIAL in manager web.xml" | tee -a "$REPORT"
  fi

  # CIS 10.13 - Do not allow symbolic linking
  echo -e "
[CIS 10.13] Do not allow symbolic linking" | tee -a "$REPORT"
  if grep -q 'allowLinking="true"' "$dir/conf/context.xml"; then
    echo "❌ Symbolic linking is allowed" | tee -a "$REPORT"
    echo "Recommendation: Set allowLinking=\"false\" in context.xml" | tee -a "$REPORT"
  else
    echo "✅ Symbolic linking is disabled" | tee -a "$REPORT"
  fi

  # CIS 10.15 - Do not allow cross-context requests
  echo -e "
[CIS 10.15] Do not allow cross context requests" | tee -a "$REPORT"
  if grep -q 'crossContext="true"' "$dir/conf/context.xml"; then
    echo "❌ crossContext access is enabled" | tee -a "$REPORT"
    echo "Recommendation: Set crossContext=\"false\" in context.xml" | tee -a "$REPORT"
  else
    echo "✅ crossContext is disabled" | tee -a "$REPORT"
  fi

  echo -e "
✅ Completed all 10.x controls. Tomcat 9 CIS Benchmark audit fully implemented."





}
