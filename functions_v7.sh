#!/bin/bash

# Apache Tomcat 7 CIS Benchmark v1.1.0 - Sections 1 to 6 ONLY
# This script checks all controls in sections 1 through 6 with real enforcement logic.

check_controls_v7() {
  local dir="$1"
  REPORT="$dir/tomcat7_cis_compliance_report.txt"
  echo "Apache Tomcat 7 Compliance Report - $(date)" > "$REPORT"

# [CIS 1.1] Remove extraneous files and directories
  echo -e "\n[CIS 1.1] Remove extraneous files and directories" | tee -a "$REPORT"
  extraneous=(examples docs manager host-manager ROOT js-examples servlet-example webdav tomcat-docs balancer admin)
  found=0
  for app in "${extraneous[@]}"; do
    if [[ -e "$dir/webapps/$app" ]] || [[ -e "$dir/server/webapps/$app" ]] || [[ -e "$dir/conf/Catalina/localhost/$app.xml" ]]; then
      echo "❌ $app found in Tomcat structure" | tee -a "$REPORT"
      found=1
    fi
  done
  if [[ $found -eq 0 ]]; then
    echo "✅ No extraneous files found" | tee -a "$REPORT"
  else
    echo "❌ Extraneous files detected – remove unused sample webapps and docs" | tee -a "$REPORT"
  fi

  # [CIS 1.2] Disable unused connectors
  echo -e "\n[CIS 1.2] Disable unused connectors" | tee -a "$REPORT"
  active_connectors=$(grep -oP '<Connector\s+[^>]*protocol="[^"]*"' "$dir/conf/server.xml")
  if [[ -n "$active_connectors" ]]; then
    echo "$active_connectors" | while read -r line; do
      echo "ℹ️ Connector found: $line" | tee -a "$REPORT"
    done
    echo "⚠️ Review server.xml to ensure only required connectors are enabled" | tee -a "$REPORT"
  else
    echo "✅ No active connectors found in server.xml" | tee -a "$REPORT"
  fi

# [CIS 2.1] Alter the Advertised server.info String
  echo -e "\n[CIS 2.1] Alter the Advertised server.info String" | tee -a "$REPORT"
  server_info_file="org/apache/catalina/util/ServerInfo.properties"
  if cd "$dir/lib" && jar xf catalina.jar "$server_info_file"; then
    info_val=$(grep server.info "$server_info_file" | cut -d= -f2)
    if [[ "$info_val" == "Apache Tomcat"* ]]; then
      echo "❌ Default server.info string found: $info_val" | tee -a "$REPORT"
      echo "Risk Level: Medium" | tee -a "$REPORT"
      echo "Recommendation: Update server.info in ServerInfo.properties and repackage catalina.jar" | tee -a "$REPORT"
    else
      echo "✅ Custom server.info value detected: $info_val" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ Could not extract ServerInfo.properties from catalina.jar" | tee -a "$REPORT"
  fi

  # [CIS 2.2] Alter the Advertised server.number String
  echo -e "\n[CIS 2.2] Alter the Advertised server.number String" | tee -a "$REPORT"
  number_val=$(grep server.number "$server_info_file" | cut -d= -f2)
  if [[ "$number_val" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "❌ Default server.number value found: $number_val" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Recommendation: Modify server.number in ServerInfo.properties" | tee -a "$REPORT"
  else
    echo "✅ Custom server.number is in use: $number_val" | tee -a "$REPORT"
  fi

  # [CIS 2.3] Alter the Advertised server.built Date
  echo -e "\n[CIS 2.3] Alter the Advertised server.built Date" | tee -a "$REPORT"
  built_val=$(grep server.built "$server_info_file" | cut -d= -f2)
  if [[ "$built_val" == *[0-9]* ]]; then
    echo "❌ Default build date detected: $built_val" | tee -a "$REPORT"
    echo "Risk Level: Low" | tee -a "$REPORT"
    echo "Recommendation: Modify server.built to a custom value in ServerInfo.properties" | tee -a "$REPORT"
  else
    echo "✅ server.built appears customized: $built_val" | tee -a "$REPORT"
  fi

  # [CIS 2.4] Disable X-Powered-By Header
  echo -e "\n[CIS 2.4] Disable X-Powered-By HTTP Header" | tee -a "$REPORT"
  if grep -q 'xpoweredBy="true"' "$dir/conf/server.xml"; then
    echo "❌ xpoweredBy is enabled in server.xml" | tee -a "$REPORT"
    echo "Risk Level: Low" | tee -a "$REPORT"
    echo "Recommendation: Set xpoweredBy="false" in all Connector elements" | tee -a "$REPORT"
  else
    echo "✅ xpoweredBy is not present or is already set to false" | tee -a "$REPORT"
  fi

  # [CIS 2.5] Disable client facing Stack Traces
  echo -e "\n[CIS 2.5] Disable client facing Stack Traces" | tee -a "$REPORT"
  if grep -q "<error-page>" "$dir/conf/web.xml"; then
    if grep -q "java.lang.Throwable" "$dir/conf/web.xml"; then
      echo "✅ <error-page> for java.lang.Throwable is configured" | tee -a "$REPORT"
    else
      echo "❌ <error-page> exists but does not handle java.lang.Throwable" | tee -a "$REPORT"
      echo "Recommendation: Add <error-page> with <exception-type>java.lang.Throwable</exception-type>" | tee -a "$REPORT"
    fi
  else
    echo "❌ No <error-page> configuration found in web.xml" | tee -a "$REPORT"
  fi

  # [CIS 2.6] Turn off TRACE
  echo -e "\n[CIS 2.6] Turn off TRACE" | tee -a "$REPORT"
  if grep -q 'allowTrace="true"' "$dir/conf/server.xml"; then
    echo "❌ TRACE is enabled via allowTrace in server.xml" | tee -a "$REPORT"
    echo "Risk Level: High" | tee -a "$REPORT"
    echo "Recommendation: Set allowTrace="false" or remove allowTrace from all Connector elements" | tee -a "$REPORT"
  else
    echo "✅ TRACE method is disabled (allowTrace not set to true)" | tee -a "$REPORT"
  fi

# [CIS 3.1] Set a nondeterministic Shutdown command value
  echo -e "\n[CIS 3.1] Set a nondeterministic Shutdown command value" | tee -a "$REPORT"
  shutdown_value=$(grep -oP '<Server port="8005" shutdown="\K[^"]+' "$dir/conf/server.xml")
  if [[ "$shutdown_value" == "SHUTDOWN" ]]; then
    echo "❌ Default shutdown value 'SHUTDOWN' found" | tee -a "$REPORT"
    echo "Risk Level: High" | tee -a "$REPORT"
    echo "Recommendation: Change shutdown string to a random nondeterministic value" | tee -a "$REPORT"
  elif [[ -n "$shutdown_value" ]]; then
    echo "✅ Non-default shutdown value set: $shutdown_value" | tee -a "$REPORT"
  else
    echo "⚠️ No shutdown attribute found in <Server> element" | tee -a "$REPORT"
  fi

  # [CIS 3.2] Disable the Shutdown port
  echo -e "\n[CIS 3.2] Disable the Shutdown port" | tee -a "$REPORT"
  if grep -q '<Server port="-1"' "$dir/conf/server.xml"; then
    echo "✅ Shutdown port is disabled (port -1)" | tee -a "$REPORT"
  else
    echo "❌ Shutdown port is not disabled" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Recommendation: Set <Server port="-1" shutdown="..."> to disable shutdown port" | tee -a "$REPORT"
  fi

# [CIS 4.1] Restrict access to $CATALINA_HOME
  echo -e "\n[CIS 4.1] Restrict access to \$CATALINA_HOME" | tee -a "$REPORT"
  if [[ -d "$dir" ]]; then
    perms=$(stat -c "%a" "$dir")
    owner=$(stat -c "%U:%G" "$dir")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 750 ]]; then
      echo "✅ $dir ownership and permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure $dir ownership or permissions ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir && chmod g-w,o-rwx $dir" | tee -a "$REPORT"
    fi
  fi

  # [CIS 4.2] Restrict access to $CATALINA_BASE
  echo -e "\n[CIS 4.2] Restrict access to \$CATALINA_BASE" | tee -a "$REPORT"
  if [[ -d "$dir" ]]; then
    perms=$(stat -c "%a" "$dir")
    owner=$(stat -c "%U:%G" "$dir")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 750 ]]; then
      echo "✅ $dir (CATALINA_BASE) ownership and permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure $dir (CATALINA_BASE) ownership or permissions ($owner, $perms)" | tee -a "$REPORT"
    fi
  fi


  # [CIS 4.3] Restrict access to conf
  echo -e "\n[CIS 4.3] Restrict access to conf" | tee -a "$REPORT"
  if [[ -e "$dir/conf" ]]; then
    perms=$(stat -c "%a" "$dir/conf")
    owner=$(stat -c "%U:%G" "$dir/conf")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ conf permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on conf ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/conf && chmod g-w,o-rwx $dir/conf" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ conf not found at $dir/conf" | tee -a "$REPORT"
  fi

  # [CIS 4.4] Restrict access to logs
  echo -e "\n[CIS 4.4] Restrict access to logs" | tee -a "$REPORT"
  if [[ -e "$dir/logs" ]]; then
    perms=$(stat -c "%a" "$dir/logs")
    owner=$(stat -c "%U:%G" "$dir/logs")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ logs permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on logs ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/logs && chmod g-w,o-rwx $dir/logs" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ logs not found at $dir/logs" | tee -a "$REPORT"
  fi

  # [CIS 4.5] Restrict access to temp
  echo -e "\n[CIS 4.5] Restrict access to temp" | tee -a "$REPORT"
  if [[ -e "$dir/temp" ]]; then
    perms=$(stat -c "%a" "$dir/temp")
    owner=$(stat -c "%U:%G" "$dir/temp")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ temp permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on temp ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/temp && chmod g-w,o-rwx $dir/temp" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ temp not found at $dir/temp" | tee -a "$REPORT"
  fi

  # [CIS 4.6] Restrict access to bin
  echo -e "\n[CIS 4.6] Restrict access to bin" | tee -a "$REPORT"
  if [[ -e "$dir/bin" ]]; then
    perms=$(stat -c "%a" "$dir/bin")
    owner=$(stat -c "%U:%G" "$dir/bin")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ bin permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on bin ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/bin && chmod g-w,o-rwx $dir/bin" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ bin not found at $dir/bin" | tee -a "$REPORT"
  fi

  # [CIS 4.7] Restrict access to webapps
  echo -e "\n[CIS 4.7] Restrict access to webapps" | tee -a "$REPORT"
  if [[ -e "$dir/webapps" ]]; then
    perms=$(stat -c "%a" "$dir/webapps")
    owner=$(stat -c "%U:%G" "$dir/webapps")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ webapps permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on webapps ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/webapps && chmod g-w,o-rwx $dir/webapps" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ webapps not found at $dir/webapps" | tee -a "$REPORT"
  fi

  # [CIS 4.8] Restrict access to catalina.policy
  echo -e "\n[CIS 4.8] Restrict access to catalina.policy" | tee -a "$REPORT"
  if [[ -e "$dir/conf/catalina.policy" ]]; then
    perms=$(stat -c "%a" "$dir/conf/catalina.policy")
    owner=$(stat -c "%U:%G" "$dir/conf/catalina.policy")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ catalina.policy permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on catalina.policy ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/conf/catalina.policy && chmod g-w,o-rwx $dir/conf/catalina.policy" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ catalina.policy not found at $dir/conf/catalina.policy" | tee -a "$REPORT"
  fi

  # [CIS 4.9] Restrict access to catalina.properties
  echo -e "\n[CIS 4.9] Restrict access to catalina.properties" | tee -a "$REPORT"
  if [[ -e "$dir/conf/catalina.properties" ]]; then
    perms=$(stat -c "%a" "$dir/conf/catalina.properties")
    owner=$(stat -c "%U:%G" "$dir/conf/catalina.properties")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ catalina.properties permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on catalina.properties ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/conf/catalina.properties && chmod g-w,o-rwx $dir/conf/catalina.properties" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ catalina.properties not found at $dir/conf/catalina.properties" | tee -a "$REPORT"
  fi

  # [CIS 4.10] Restrict access to context.xml
  echo -e "\n[CIS 4.10] Restrict access to context.xml" | tee -a "$REPORT"
  if [[ -e "$dir/conf/context.xml" ]]; then
    perms=$(stat -c "%a" "$dir/conf/context.xml")
    owner=$(stat -c "%U:%G" "$dir/conf/context.xml")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ context.xml permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on context.xml ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/conf/context.xml && chmod g-w,o-rwx $dir/conf/context.xml" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ context.xml not found at $dir/conf/context.xml" | tee -a "$REPORT"
  fi

  # [CIS 4.11] Restrict access to logging.properties
  echo -e "\n[CIS 4.11] Restrict access to logging.properties" | tee -a "$REPORT"
  if [[ -e "$dir/conf/logging.properties" ]]; then
    perms=$(stat -c "%a" "$dir/conf/logging.properties")
    owner=$(stat -c "%U:%G" "$dir/conf/logging.properties")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ logging.properties permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on logging.properties ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/conf/logging.properties && chmod g-w,o-rwx $dir/conf/logging.properties" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ logging.properties not found at $dir/conf/logging.properties" | tee -a "$REPORT"
  fi

  # [CIS 4.12] Restrict access to server.xml
  echo -e "\n[CIS 4.12] Restrict access to server.xml" | tee -a "$REPORT"
  if [[ -e "$dir/conf/server.xml" ]]; then
    perms=$(stat -c "%a" "$dir/conf/server.xml")
    owner=$(stat -c "%U:%G" "$dir/conf/server.xml")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ server.xml permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on server.xml ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/conf/server.xml && chmod g-w,o-rwx $dir/conf/server.xml" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ server.xml not found at $dir/conf/server.xml" | tee -a "$REPORT"
  fi

  # [CIS 4.13] Restrict access to tomcat-users.xml
  echo -e "\n[CIS 4.13] Restrict access to tomcat-users.xml" | tee -a "$REPORT"
  if [[ -e "$dir/conf/tomcat-users.xml" ]]; then
    perms=$(stat -c "%a" "$dir/conf/tomcat-users.xml")
    owner=$(stat -c "%U:%G" "$dir/conf/tomcat-users.xml")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ tomcat-users.xml permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on tomcat-users.xml ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/conf/tomcat-users.xml && chmod g-w,o-rwx $dir/conf/tomcat-users.xml" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ tomcat-users.xml not found at $dir/conf/tomcat-users.xml" | tee -a "$REPORT"
  fi

  # [CIS 4.14] Restrict access to web.xml
  echo -e "\n[CIS 4.14] Restrict access to web.xml" | tee -a "$REPORT"
  if [[ -e "$dir/conf/web.xml" ]]; then
    perms=$(stat -c "%a" "$dir/conf/web.xml")
    owner=$(stat -c "%U:%G" "$dir/conf/web.xml")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
      echo "✅ web.xml permissions are secure ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure permissions or ownership on web.xml ($owner, $perms)" | tee -a "$REPORT"
      echo "Recommendation: chown tomcat_admin:tomcat $dir/conf/web.xml && chmod g-w,o-rwx $dir/conf/web.xml" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ web.xml not found at $dir/conf/web.xml" | tee -a "$REPORT"
  fi

# [CIS 5.1] Use secure Realms
  echo -e "\n[CIS 5.1] Use secure Realms" | tee -a "$REPORT"
  insecure_realms=$(grep -E 'Realm className="org.apache.catalina.realm.(MemoryRealm|UserDatabaseRealm|JDBCRealm|JAASRealm)"' "$dir/conf/server.xml")
  if [[ -n "$insecure_realms" ]]; then
    echo "❌ Insecure Realms detected:" | tee -a "$REPORT"
    echo "$insecure_realms" | tee -a "$REPORT"
    echo "Recommendation: Use JNDIRealm or DataSourceRealm for production." | tee -a "$REPORT"
  else
    echo "✅ No insecure Realm configurations found" | tee -a "$REPORT"
  fi

  # [CIS 5.2] Use LockOutRealm
  echo -e "\n[CIS 5.2] Use LockOutRealm" | tee -a "$REPORT"
  if grep -q "LockOutRealm" "$dir/conf/server.xml"; then
    echo "✅ LockOutRealm is configured to prevent brute-force logins" | tee -a "$REPORT"
  else
    echo "❌ LockOutRealm is not present in server.xml" | tee -a "$REPORT"
    echo "Risk Level: Medium" | tee -a "$REPORT"
    echo "Recommendation: Wrap authentication Realm in <LockOutRealm> in server.xml" | tee -a "$REPORT"
  fi

# [CIS 6.1] Use the secure flag for all cookies
  echo -e "\n[CIS 6.1] Use the secure flag for all cookies" | tee -a "$REPORT"
  if grep -q "<Context" "$dir/conf/context.xml"; then
    if grep -q 'useHttpOnly="true"' "$dir/conf/context.xml" && grep -q 'secure="true"' "$dir/conf/context.xml"; then
      echo "✅ secure and HttpOnly flags are enabled in context.xml" | tee -a "$REPORT"
    else
      echo "❌ Missing secure and/or HttpOnly attributes in context.xml" | tee -a "$REPORT"
      echo "Recommendation: Add useHttpOnly="true" and secure="true" to the <Context> element" | tee -a "$REPORT"
    fi
  else
    echo "⚠️ No <Context> element found in context.xml" | tee -a "$REPORT"
  fi

  # [CIS 6.2] Disable SSLv2 and SSLv3
  echo -e "\n[CIS 6.2] Disable SSLv2 and SSLv3" | tee -a "$REPORT"
  if grep -q 'sslProtocols="TLS' "$dir/conf/server.xml"; then
    echo "✅ SSLv2/SSLv3 protocols are not enabled; TLS is used" | tee -a "$REPORT"
  else
    echo "❌ sslProtocols attribute not found or not properly set" | tee -a "$REPORT"
    echo "Recommendation: Set sslProtocols="TLS" on all SSL-enabled <Connector> elements" | tee -a "$REPORT"
  fi

  # [CIS 6.3] Ensure scheme is set accurately
  echo -e "\n[CIS 6.3] Ensure scheme is set accurately" | tee -a "$REPORT"
  if grep -q '<Connector.*scheme="https"' "$dir/conf/server.xml"; then
    echo "✅ HTTPS scheme set in Connector" | tee -a "$REPORT"
  else
    echo "❌ Connector scheme is not set to https" | tee -a "$REPORT"
    echo "Recommendation: Add scheme="https" to all SSL-enabled Connector definitions" | tee -a "$REPORT"
  fi

  # [CIS 6.4] Ensure secure=true for SSL Connectors
  echo -e "\n[CIS 6.4] Ensure secure=true for SSL Connectors" | tee -a "$REPORT"
  if grep -q '<Connector.*SSLEnabled="true".*secure="true"' "$dir/conf/server.xml"; then
    echo "✅ secure attribute set correctly for SSL-enabled Connectors" | tee -a "$REPORT"
  else
    echo "❌ secure attribute is not set correctly for SSL-enabled Connectors" | tee -a "$REPORT"
    echo "Recommendation: Ensure secure="true" in all <Connector SSLEnabled="true"> blocks" | tee -a "$REPORT"
  fi

  # [CIS 6.5] Ensure SSLProtocol is TLS
  echo -e "\n[CIS 6.5] Ensure SSLProtocol is TLS" | tee -a "$REPORT"
  if grep -q '<Connector.*SSLEnabled="true".*sslProtocol="TLS' "$dir/conf/server.xml"; then
    echo "✅ sslProtocol is set to TLS" | tee -a "$REPORT"
  else
    echo "❌ sslProtocol is not explicitly set to TLS" | tee -a "$REPORT"
    echo "Recommendation: Add sslProtocol="TLS" to all <Connector SSLEnabled="true"> elements" | tee -a "$REPORT"
  fi


  # [CIS 7.1] Ensure log rotation is configured
  echo -e "
[CIS 7.1] Ensure log rotation is configured" | tee -a "$REPORT"
  if grep -q 'FileHandler' "$dir/conf/logging.properties"; then
    if grep -q 'rotatable=true' "$dir/conf/logging.properties"; then
      echo "✅ Log rotation is enabled via rotatable=true" | tee -a "$REPORT"
    else
      echo "❌ Log rotation not explicitly configured" | tee -a "$REPORT"
      echo "Recommendation: Enable rotatable=true in logging.properties" | tee -a "$REPORT"
    fi
  else
    echo "❌ FileHandler configuration not found in logging.properties" | tee -a "$REPORT"
  fi

  # [CIS 7.2] Ensure logs are stored in a dedicated directory
  echo -e "
[CIS 7.2] Ensure logs are stored in a dedicated directory" | tee -a "$REPORT"
  if [[ -d "$dir/logs" ]]; then
    echo "✅ Dedicated logs directory exists: $dir/logs" | tee -a "$REPORT"
  else
    echo "❌ logs directory does not exist" | tee -a "$REPORT"
  fi

  # [CIS 7.3] Restrict access to logs
  echo -e "
[CIS 7.3] Restrict access to logs" | tee -a "$REPORT"
  if [[ -e "$dir/logs" ]]; then
    perms=$(stat -c "%a" "$dir/logs")
    owner=$(stat -c "%U:%G" "$dir/logs")
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 750 ]]; then
      echo "✅ logs directory has secure ownership and permissions ($owner, $perms)" | tee -a "$REPORT"
    else
      echo "❌ Insecure ownership or permissions on logs ($owner, $perms)" | tee -a "$REPORT"
    fi
  fi

  # [CIS 7.4] Do not log sensitive information
  echo -e "
[CIS 7.4] Do not log sensitive information" | tee -a "$REPORT"
  sensitive_keywords=(password passwd secret key token)
  sensitive_found=0
  for log in "$dir"/logs/*; do
    for word in "${sensitive_keywords[@]}"; do
      if grep -i "$word" "$log" &>/dev/null; then
        echo "❌ Sensitive data found in $log (keyword: $word)" | tee -a "$REPORT"
        sensitive_found=1
      fi
    done
  done
  if [[ $sensitive_found -eq 0 ]]; then
    echo "✅ No sensitive information detected in log files" | tee -a "$REPORT"
  fi

  # [CIS 7.5] Ensure logging level is appropriate
  echo -e "
[CIS 7.5] Ensure logging level is appropriate" | tee -a "$REPORT"
  if grep -q '^org.apache.catalina.level = FINE' "$dir/conf/logging.properties"; then
    echo "❌ Logging level is too verbose (FINE)" | tee -a "$REPORT"
    echo "Recommendation: Set to INFO or WARNING unless required for debugging" | tee -a "$REPORT"
  else
    echo "✅ Logging level is appropriate" | tee -a "$REPORT"
  fi

  # [CIS 7.6] Enable access log valve
  echo -e "
[CIS 7.6] Enable access log valve" | tee -a "$REPORT"
  if grep -q 'AccessLogValve' "$dir/conf/server.xml"; then
    echo "✅ AccessLogValve is configured" | tee -a "$REPORT"
  else
    echo "❌ AccessLogValve not found in server.xml" | tee -a "$REPORT"
    echo "Recommendation: Enable <Valve className="org.apache.catalina.valves.AccessLogValve" ...>" | tee -a "$REPORT"
  fi

  # [CIS 7.7] Protect access log integrity
  echo -e "
[CIS 7.7] Protect access log integrity" | tee -a "$REPORT"
  if [[ -e "$dir/logs/localhost_access_log."* ]]; then
    perms=$(stat -c "%a" "$dir/logs/localhost_access_log."* | sort -u)
    owner=$(stat -c "%U:%G" "$dir/logs/localhost_access_log."* | sort -u)
    echo "Log file permissions: $perms" | tee -a "$REPORT"
    echo "Log file ownership: $owner" | tee -a "$REPORT"
    echo "✅ Manual review required for access log rotation and integrity enforcement" | tee -a "$REPORT"
  else
    echo "⚠️ Access logs not found (localhost_access_log.*)" | tee -a "$REPORT"
  fi


  # [CIS 8.1] Configure Catalina Policy
  echo -e "\n[CIS 8.1] Configure Catalina Policy" | tee -a "$REPORT"
  policy_file="$dir/conf/catalina.policy"
  if [[ -f "$policy_file" ]]; then
    echo "✅ catalina.policy file found" | tee -a "$REPORT"
    grep -E "^grant|^permission" "$policy_file" | grep -v "//" | while read -r line; do
      echo "📜 $line" | tee -a "$REPORT"
    done
    custom_permissions=$(grep -vE '^//|^\s*$' "$policy_file" | grep -c 'permission')
    if [[ $custom_permissions -gt 0 ]]; then
      echo "✅ Policy includes $custom_permissions permission definitions" | tee -a "$REPORT"
    else
      echo "❌ No active permission definitions found in catalina.policy" | tee -a "$REPORT"
    fi
  else
    echo "❌ catalina.policy not found at $policy_file" | tee -a "$REPORT"
    echo "Recommendation: Restore catalina.policy from a known good backup or configure it securely" | tee -a "$REPORT"
  fi


  # [CIS 9.1] Remove default ROOT web application
  echo -e "
[CIS 9.1] Remove default ROOT web application" | tee -a "$REPORT"
  if [[ -d "$dir/webapps/ROOT" ]]; then
    echo "❌ Default ROOT web application is present" | tee -a "$REPORT"
    echo "Recommendation: Delete $dir/webapps/ROOT to reduce attack surface" | tee -a "$REPORT"
  else
    echo "✅ Default ROOT web application is not present" | tee -a "$REPORT"
  fi

  # [CIS 9.2] Remove example applications
  echo -e "
[CIS 9.2] Remove example applications" | tee -a "$REPORT"
  examples_found=0
  for app in examples docs host-manager manager; do
    if [[ -e "$dir/webapps/$app" ]] || [[ -e "$dir/conf/Catalina/localhost/$app.xml" ]]; then
      echo "❌ Example application or config present: $app" | tee -a "$REPORT"
      examples_found=1
    fi
  done
  if [[ $examples_found -eq 0 ]]; then
    echo "✅ No example applications detected" | tee -a "$REPORT"
  else
    echo "Recommendation: Remove all example apps and associated XML files from webapps/ and conf/localhost/" | tee -a "$REPORT"
  fi

  # [CIS 9.3] Remove default index.jsp files
  echo -e "
[CIS 9.3] Remove default index.jsp files" | tee -a "$REPORT"
  default_indexes=$(find "$dir/webapps" -type f -name "index.jsp" 2>/dev/null)
  if [[ -n "$default_indexes" ]]; then
    echo "❌ Default index.jsp files found:" | tee -a "$REPORT"
    echo "$default_indexes" | tee -a "$REPORT"
    echo "Recommendation: Delete unused index.jsp files to avoid default page exposure" | tee -a "$REPORT"
  else
    echo "✅ No default index.jsp files found" | tee -a "$REPORT"
  fi


  # [CIS 10.1] Disable autoDeploy and deployOnStartup
  echo -e "\n[CIS 10.1] Disable autoDeploy and deployOnStartup" | tee -a "$REPORT"
  if grep -q 'autoDeploy="true"' "$dir/conf/server.xml" || grep -q 'deployOnStartup="true"' "$dir/conf/server.xml"; then
    echo "❌ autoDeploy or deployOnStartup is enabled" | tee -a "$REPORT"
    echo "Recommendation: Set autoDeploy="false" and deployOnStartup="false" in Host element" | tee -a "$REPORT"
  else
    echo "✅ autoDeploy and deployOnStartup are disabled" | tee -a "$REPORT"
  fi

  # [CIS 10.2] Configure the URIEncoding as UTF-8
  echo -e "\n[CIS 10.2] Configure the URIEncoding as UTF-8" | tee -a "$REPORT"
  if grep -q 'URIEncoding="UTF-8"' "$dir/conf/server.xml"; then
    echo "✅ URIEncoding is set to UTF-8" | tee -a "$REPORT"
  else
    echo "❌ URIEncoding is not configured or not set to UTF-8" | tee -a "$REPORT"
  fi

  # [CIS 10.3] Configure the Context attribute swallowOutput
  echo -e "\n[CIS 10.3] Configure swallowOutput" | tee -a "$REPORT"
  if grep -q 'swallowOutput="true"' "$dir/conf/context.xml"; then
    echo "✅ swallowOutput="true" is set in context.xml" | tee -a "$REPORT"
  else
    echo "❌ swallowOutput is not configured or set incorrectly" | tee -a "$REPORT"
  fi

  # [CIS 10.4] Remove unnecessary Services
  echo -e "\n[CIS 10.4] Remove unnecessary Services" | tee -a "$REPORT"
  service_count=$(grep -c "<Service" "$dir/conf/server.xml")
  if [[ $service_count -gt 1 ]]; then
    echo "❌ Multiple <Service> elements found: $service_count" | tee -a "$REPORT"
    echo "Recommendation: Retain only required Service definitions" | tee -a "$REPORT"
  else
    echo "✅ Single <Service> element found" | tee -a "$REPORT"
  fi

  # [CIS 10.5] Limit the number of threads
  echo -e "\n[CIS 10.5] Limit the number of threads" | tee -a "$REPORT"
  if grep -q 'maxThreads=' "$dir/conf/server.xml"; then
    thread_limit=$(grep 'maxThreads=' "$dir/conf/server.xml" | grep -oP 'maxThreads="\K[0-9]+')
    echo "ℹ️ maxThreads value found: $thread_limit" | tee -a "$REPORT"
  else
    echo "❌ maxThreads not configured in server.xml" | tee -a "$REPORT"
  fi

  # [CIS 10.6] Enable SecurityManager (not typically used in Tomcat 7+)
  echo -e "\n[CIS 10.6] Enable SecurityManager" | tee -a "$REPORT"
  if grep -q 'security' "$dir/bin/startup.sh"; then
    echo "✅ SecurityManager is referenced in startup.sh" | tee -a "$REPORT"
  else
    echo "⚠️ SecurityManager is not explicitly referenced (manual inspection recommended)" | tee -a "$REPORT"
  fi

  # [CIS 10.7] Remove .DS_Store or Thumbs.db
  echo -e "\n[CIS 10.7] Remove OS metadata files" | tee -a "$REPORT"
  if find "$dir" -type f \( -name ".DS_Store" -o -name "Thumbs.db" \) | grep -q .; then
    echo "❌ OS metadata files detected" | tee -a "$REPORT"
    echo "Recommendation: Delete all .DS_Store or Thumbs.db files" | tee -a "$REPORT"
  else
    echo "✅ No OS metadata files present" | tee -a "$REPORT"
  fi

  # [CIS 10.8] Validate XML parser settings (XXE hardening)
  echo -e "\n[CIS 10.8] Validate XML parser settings for XXE protection" | tee -a "$REPORT"
  if grep -q 'disallow-doctype-decl' "$dir/conf/web.xml"; then
    echo "✅ DOCTYPE declarations are disallowed (XXE mitigation enabled)" | tee -a "$REPORT"
  else
    echo "❌ DOCTYPE declarations not disallowed in web.xml" | tee -a "$REPORT"
  fi

  # [CIS 10.9 - 10.19] Placeholder
  echo -e "\n[CIS 10.9 - 10.19] Remaining checks to be implemented per policy specification." | tee -a "$REPORT"


  # [CIS 10.9] Disable the Invoker Servlet
  echo -e "
[CIS 10.9] Disable the Invoker Servlet" | tee -a "$REPORT"
  if grep -q "invoker" "$dir/conf/web.xml"; then
    echo "❌ Invoker servlet is defined in web.xml" | tee -a "$REPORT"
    echo "Recommendation: Remove or comment out the invoker servlet mapping" | tee -a "$REPORT"
  else
    echo "✅ Invoker servlet is not present" | tee -a "$REPORT"
  fi

  # [CIS 10.10] Disable directory listings
  echo -e "
[CIS 10.10] Disable directory listings" | tee -a "$REPORT"
  if grep -q '<init-param><param-name>listings</param-name><param-value>true</param-value>' "$dir/conf/web.xml"; then
    echo "❌ Directory listings are enabled" | tee -a "$REPORT"
    echo "Recommendation: Set <param-value>false</param-value> for listings in web.xml" | tee -a "$REPORT"
  else
    echo "✅ Directory listings are disabled or not configured" | tee -a "$REPORT"
  fi

  # [CIS 10.11] Set file encoding to UTF-8
  echo -e "
[CIS 10.11] Set file encoding to UTF-8" | tee -a "$REPORT"
  if grep -q 'file.encoding=UTF-8' "$dir/bin/setenv.sh"; then
    echo "✅ file.encoding=UTF-8 is set in setenv.sh" | tee -a "$REPORT"
  else
    echo "❌ file.encoding=UTF-8 is not found in setenv.sh" | tee -a "$REPORT"
    echo "Recommendation: Add JAVA_OPTS including -Dfile.encoding=UTF-8 to setenv.sh" | tee -a "$REPORT"
  fi

  # [CIS 10.12] Set character encoding filter
  echo -e "
[CIS 10.12] Set character encoding filter" | tee -a "$REPORT"
  if grep -q 'CharacterEncodingFilter' "$dir/conf/web.xml"; then
    echo "✅ CharacterEncodingFilter is configured in web.xml" | tee -a "$REPORT"
  else
    echo "❌ CharacterEncodingFilter is not found in web.xml" | tee -a "$REPORT"
  fi

  # [CIS 10.13] Prevent deployment of applications with unescaped characters
  echo -e "
[CIS 10.13] Prevent deployment of applications with unescaped characters" | tee -a "$REPORT"
  if grep -q 'rejectIllegalHeader="true"' "$dir/conf/server.xml"; then
    echo "✅ rejectIllegalHeader is set to true" | tee -a "$REPORT"
  else
    echo "❌ rejectIllegalHeader is not set" | tee -a "$REPORT"
    echo "Recommendation: Add rejectIllegalHeader="true" to <Connector> definitions" | tee -a "$REPORT"
  fi

  # [CIS 10.14] Disable session persistence
  echo -e "
[CIS 10.14] Disable session persistence" | tee -a "$REPORT"
  if grep -q '<Manager pathname=""' "$dir/conf/context.xml"; then
    echo "✅ Session persistence is disabled via pathname=""" | tee -a "$REPORT"
  else
    echo "❌ Session persistence may be enabled (pathname not set to empty)" | tee -a "$REPORT"
  fi

  # [CIS 10.15] Configure session timeout
  echo -e "
[CIS 10.15] Configure session timeout" | tee -a "$REPORT"
  timeout=$(grep -oP '(?<=<session-timeout>).*?(?=</session-timeout>)' "$dir/conf/web.xml" | head -n1)
  if [[ -n "$timeout" && "$timeout" -le 30 ]]; then
    echo "✅ Session timeout configured: $timeout minutes" | tee -a "$REPORT"
  else
    echo "❌ Session timeout not configured or is too long" | tee -a "$REPORT"
    echo "Recommendation: Set <session-timeout> to 30 or fewer minutes in web.xml" | tee -a "$REPORT"
  fi

  # [CIS 10.16] Restrict HTTP methods
  echo -e "
[CIS 10.16] Restrict HTTP methods" | tee -a "$REPORT"
  if grep -q "http-method" "$dir/conf/web.xml"; then
    echo "✅ HTTP method restrictions are defined in web.xml" | tee -a "$REPORT"
  else
    echo "❌ No HTTP method restrictions found in web.xml" | tee -a "$REPORT"
  fi

  # [CIS 10.17] Use TLS for all communication
  echo -e "
[CIS 10.17] Use TLS for all communication" | tee -a "$REPORT"
  if grep -q 'SSLEnabled="true"' "$dir/conf/server.xml"; then
    echo "✅ TLS (SSLEnabled="true") is configured in server.xml" | tee -a "$REPORT"
  else
    echo "❌ TLS (SSLEnabled) not enabled in server.xml" | tee -a "$REPORT"
  fi

  # [CIS 10.18] Avoid weak cipher suites
  echo -e "
[CIS 10.18] Avoid weak cipher suites" | tee -a "$REPORT"
  if grep -q 'ciphers=' "$dir/conf/server.xml"; then
    ciphers=$(grep 'ciphers=' "$dir/conf/server.xml")
    echo "ℹ️ Configured ciphers: $ciphers" | tee -a "$REPORT"
    echo "✅ Manual validation recommended to ensure only strong cipher suites are listed" | tee -a "$REPORT"
  else
    echo "❌ No cipher suites explicitly configured in server.xml" | tee -a "$REPORT"
  fi

  # [CIS 10.19] Use secure session cookies
  echo -e "
[CIS 10.19] Use secure session cookies" | tee -a "$REPORT"
  if grep -q '<cookie-config>' "$dir/conf/web.xml"; then
    echo "✅ Secure cookie settings are configured in web.xml" | tee -a "$REPORT"
  else
    echo "❌ Secure cookie settings not found in web.xml" | tee -a "$REPORT"
    echo "Recommendation: Use <cookie-config><secure>true</secure><http-only>true</http-only></cookie-config>" | tee -a "$REPORT"
  fi

}
