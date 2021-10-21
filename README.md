# `trombik.opensearch`

`ansible` role to manage `opensearch`.

## for all users

The role assumes the service is listening on `localhost`.

# Requirements

By default, the role uses `trombik.x509_certificate` to manage X509
certificates. The role does not list `trombik.x509_certificate` as a
dependency because TLS is not mandatory.

# Role Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `opensearch_user` | user name of `opensearch` | `{{ __opensearch_user }}` |
| `opensearch_group` | group name of `opensearch` | `{{ __opensearch_group }}` |
| `opensearch_log_dir` | path to log directory | `{{ __opensearch_log_dir }}` |
| `opensearch_db_dir` | path to data directory | `{{ __opensearch_db_dir }}` |
| `opensearch_scripts_dir` | path to script directory | `{{ __opensearch_scripts_dir }}` |
| `opensearch_plugins_dir` | path to plug-in directory | `{{ __opensearch_plugins_dir }}` |
| `opensearch_plugin_command` | path to `opensearch-plugin` command | `{{ __opensearch_plugin_command }}` |
| `opensearch_plugins` | a list of plugins (see below) | `[]` |
| `opensearch_service` | service name of `opensearch` | `{{ __opensearch_service }}` |
| `opensearch_package` | package name of `opensearch` | `{{ __opensearch_package }}` |
| `opensearch_conf_dir` | path to configuration directory | `{{ __opensearch_conf_dir }}` |
| `opensearch_jvm_options` | JVM options (see the example playbook) | `""` |
| `opensearch_conf_file` | path to `opensearch.yml` | `{{ opensearch_conf_dir }}/opensearch.yml` |
| `opensearch_flags` | extra flags for startup scripts | `""` |
| `opensearch_config` | the content of `opensearch.yml` | `""` |
| `opensearch_config_log4j2_properties` | the content of `log4j2.properties` | `""` |
| `opensearch_http_port` | listen port of `opensearch` | `9200` |
| `opensearch_java_home` | `JAVA_HOME` environment variable | `{{ __opensearch_java_home }}` |
| `opensearch_extra_plugin_files` | a list of extra files for plug-ins (see below) | `[]` |
| `opensearch_include_role_x509_certificate` | if true, include `trombik.x509_certificate` during the play (`trombik.x509_certificate` must be listed in `requirements.yml`) | `yes` |

## `opensearch_plugins`

This is a list of plug-ins. An element of the list is a dict.

| Key | Description | Mandatory? |
|-----|-------------|------------|
| `name` | name of the plug-in | yes |
| `src` | the source of the plug-in, usually an URL | no |

## `opensearch_extra_plugin_files`

This variable is a list of files for plug-ins. An element of the list is a
dict.

| Key | Description | Mandatory? |
|-----|-------------|------------|
| `path` | relative path to the file from `opensearch_plugins_dir` | yes |
| `type` | either `yaml` or  `raw`. when the type is `yaml`, the value of `content` is rendered as YAML. when the type is `raw`, the value of `content` is rendered as-is. when the value of `state` is omitted, or `present`, `type` must be specified. | no |
| `mode` | file mode of the file | no |
| `owner` | owner of the file | no |
| `group` | group of the file | no |
| `state` | either `present` or `absent`. `present` creates the file. `absent` deletes the file. the default is `present` | no |
| `content` | the content of the file (see also `type` above) | no |
| `post_command` | a dict for `ansible.builtin.command` | no |

`post_command` is a dict to run a command after the status of the item is
changed. The variable is passed to `ansible.builtin.command` (not
`ansible.builtin.shell`).

It accepts the following keys:

| Key | Description | Mandatory? |
|-----|-------------|------------|
| `cmd` | The command to run | yes |
| `args` | A dict for `args`. Currently `chdir`, `creates`, and `removes` are supported. | no |

`post_command` is primarily designed for `securityadmin.sh`.
See
[Apply changes using securityadmin.sh](https://opensearch.org/docs/latest/security-plugin/configuration/security-admin/)
for more details.

## Debian

| Variable | Default |
|----------|---------|
| `__opensearch_user` | `opensearch` |
| `__opensearch_group` | `opensearch` |
| `__opensearch_log_dir` | `/var/log/opensearch` |
| `__opensearch_db_dir` | `/var/lib/opensearch` |
| `__opensearch_package` | `opensearch` |
| `__opensearch_conf_dir` | `/etc/opensearch` |
| `__opensearch_scripts_dir` | `""` |
| `__opensearch_plugins_dir` | `/usr/share/opensearch/plugins` |
| `__opensearch_plugin_command` | `/usr/share/opensearch/bin/opensearch-plugin` |
| `__opensearch_service` | `opensearch` |
| `__opensearch_java_home` | `""` |

## FreeBSD

| Variable | Default |
|----------|---------|
| `__opensearch_user` | `opensearch` |
| `__opensearch_group` | `opensearch` |
| `__opensearch_log_dir` | `/var/log/opensearch` |
| `__opensearch_db_dir` | `/var/db/opensearch` |
| `__opensearch_package` | `textproc/opensearch` |
| `__opensearch_conf_dir` | `/usr/local/etc/opensearch` |
| `__opensearch_scripts_dir` | `""` |
| `__opensearch_plugins_dir` | `/usr/local/lib/opensearch/plugins` |
| `__opensearch_plugin_command` | `/usr/local/lib/opensearch/bin/opensearch-plugin` |
| `__opensearch_service` | `opensearch` |
| `__opensearch_java_home` | `/usr/local` |

## RedHat

| Variable | Default |
|----------|---------|
| `__opensearch_user` | `opensearch` |
| `__opensearch_group` | `opensearch` |
| `__opensearch_log_dir` | `/var/log/opensearch` |
| `__opensearch_db_dir` | `/var/lib/opensearch` |
| `__opensearch_package` | `opensearch` |
| `__opensearch_conf_dir` | `/etc/opensearch` |
| `__opensearch_scripts_dir` | `""` |
| `__opensearch_plugins_dir` | `/usr/share/opensearch/plugins` |
| `__opensearch_plugin_command` | `/usr/share/opensearch/bin/opensearch-plugin` |
| `__opensearch_service` | `opensearch` |
| `__opensearch_java_home` | `""` |

# Dependencies

- [`trombik.x509_certificate`](https://github.com/trombik/ansible-role-x509_certificate) when `opensearch_include_role_x509_certificate` is true

# Example Playbook

```yaml
---
- hosts: localhost
  roles:
    - role: trombik.freebsd_pkg_repo
      when: ansible_os_family == "FreeBSD"
    - role: trombik.apt_repo
      when: ansible_os_family == "Debian"
    - role: trombik.redhat_repo
      when: ansible_os_family == "RedHat"
    - role: trombik.java
    - role: trombik.sysctl
    - ansible-role-opensearch
    - role: trombik.opensearch_dashboards
  vars:
    freebsd_pkg_repo:
      local:
        enabled: "true"
        url: "http://pkg.i.trombik.org/{{ ansible_distribution_version | regex_replace('\\.') }}{{ ansible_architecture }}-default-default"
        mirror_type: none
        priority: 100
        state: present
    apt_repo_enable_apt_transport_https: yes
    apt_repo_to_add:
      - ppa:openjdk-r/ppa
      - deb [arch=amd64] https://d3g5vo6xdbdb9a.cloudfront.net/apt stable main
      - deb https://artifacts.elastic.co/packages/oss-7.x/apt stable main
    apt_repo_keys_to_add:
      - https://artifacts.elastic.co/GPG-KEY-opensearch
      - https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opensearch
    redhat_repo:
      opensearch7:
        baseurl: https://artifacts.elastic.co/packages/oss-7.x/yum
        gpgkey: https://artifacts.elastic.co/GPG-KEY-opensearch
        gpgcheck: yes
        enabled: yes
      opensearch:
        baseurl: https://d3g5vo6xdbdb9a.cloudfront.net/yum/noarch/
        gpgkey: https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opensearch
        enabled: yes
        gpgcheck: yes
    os_opensearch_extra_packages:
      FreeBSD: []
      Debian:
        # XXX install opensearch-oss that opensearch
        # requires.
        - opensearch-oss=7.10.2
        - unzip
      RedHat: []
    opensearch_extra_packages: "{{ os_opensearch_extra_packages[ansible_os_family] }}"
    os_java_packages:
      FreeBSD:
        - openjdk11
      Debian:
        - openjdk-11-jdk
      RedHat:
        - java-11-openjdk-devel
    java_packages: "{{ os_java_packages[ansible_os_family] }}"
    os_sysctl:
      FreeBSD:
        kern.maxfilesperproc: 65536
        security.bsd.unprivileged_mlock: 1
      Debian: []
      RedHat: []
    sysctl: "{{ os_sysctl[ansible_os_family] }}"


    os_opensearch_package:
      FreeBSD: "{{ __opensearch_package }}"
      Debian: "{{ __opensearch_package }}"
      RedHat: opensearch-1.13.2
    opensearch_package: "{{ os_opensearch_package[ansible_os_family] }}"
    os_opensearch_flags:
      FreeBSD: ""
      Debian: |
        ES_PATH_CONF={{ opensearch_conf_dir }}
        ES_STARTUP_SLEEP_TIME=5
        MAX_OPEN_FILES=65535
        MAX_LOCKED_MEMORY=unlimited
      RedHat: |
        ES_PATH_CONF={{ opensearch_conf_dir }}
        ES_STARTUP_SLEEP_TIME=5
        MAX_OPEN_FILES=65535
        MAX_LOCKED_MEMORY=unlimited
    opensearch_flags: "{{ os_opensearch_flags[ansible_os_family] }}"
    opensearch_jvm_options: |
      -Xms1024m
      -Xmx1024m
      -Xmx1g
      -Des.networkaddress.cache.ttl=60
      -Des.networkaddress.cache.negative.ttl=10
      -XX:+AlwaysPreTouch
      -Xss1m
      -Djava.awt.headless=true
      -Dfile.encoding=UTF-8
      -Djna.nosys=true
      -XX:-OmitStackTraceInFastThrow
      -Dio.netty.noUnsafe=true
      -Dio.netty.noKeySetOptimization=true
      -Dio.netty.recycler.maxCapacityPerThread=0
      -Dlog4j.shutdownHookEnabled=false
      -Dlog4j2.disable.jmx=true
      -Djava.io.tmpdir=/tmp
      -XX:+HeapDumpOnOutOfMemoryError
      -XX:HeapDumpPath=data
      -XX:ErrorFile={{ opensearch_log_dir }}/hs_err_pid%p.log
      -XX:+UseCompressedOops
    opensearch_config:
      discovery.type: single-node
      network.publish_host: ["10.0.2.15"]
      path.data: "{{ opensearch_db_dir }}"
      http.port: "{{ opensearch_http_port }}"
      path.logs: "{{ opensearch_log_dir }}"
      node.data: "true"
      http.compression: "true"
      network.host:
        - _local_
        - _site_
      cluster.name: testcluster
      node.name: testnode
      http.cors.enabled: "true"
      http.cors.allow-origin: "*"
      http.cors.max-age: 86400
      http.cors.allow-methods: "OPTIONS, HEAD, GET, POST, PUT, DELETE"
      http.cors.allow-headers: "X-Requested-With, Content-Type, Content-Length"
      http.cors.allow-credentials: "true"
      # _________________________TLS
      plugins.security.ssl.transport.pemcert_filepath: node.pem
      plugins.security.ssl.transport.pemkey_filepath: node-key.pem
      plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem
      plugins.security.ssl.transport.enforce_hostname_verification: false
      plugins.security.ssl.http.enabled: true
      plugins.security.ssl.http.pemcert_filepath: node.pem
      plugins.security.ssl.http.pemkey_filepath: node-key.pem
      plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem
      plugins.security.allow_unsafe_democertificates: true
      plugins.security.allow_default_init_securityindex: true
      plugins.security.authcz.admin_dn:
        - CN=Admin,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU
      plugins.security.nodes_dn:
        - CN=localhost,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU
      plugins.security.audit.type: internal_opensearch
      plugins.security.enable_snapshot_restore_privilege: true
      plugins.security.check_snapshot_restore_write_privileges: true
      plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
      plugins.security.system_indices.enabled: true
      plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opendistro-asynchronous-search-response*"]

      cluster.routing.allocation.disk.threshold_enabled: false
      node.max_local_storage_nodes: 3

    project_security_plugin_dir: "{{ opensearch_plugins_dir }}/opensearch-security"
    project_securityadmin_bin: "{{ project_security_plugin_dir }}/tools/securityadmin.sh"
    project_security_plugin_post_command:
      cmd: "{{ project_securityadmin_bin }} -icl -nhnv -cacert {{ opensearch_conf_dir }}/root-ca.pem -cert {{ opensearch_conf_dir }}/admin.pem -key {{ opensearch_conf_dir }}/admin-key.pem"
      args:
        chdir: "{{ project_security_plugin_dir }}/securityconfig"

    opensearch_plugins: []
    opensearch_extra_plugin_files:
      - path: opensearch-security/securityconfig/action_groups.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/action_groups.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"
      - path: opensearch-security/securityconfig/audit.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/audit.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"
      - path: opensearch-security/securityconfig/config.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/config.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"
      - path: opensearch-security/securityconfig/internal_users.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/internal_users.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"
      - path: opensearch-security/securityconfig/nodes_dn.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/nodes_dn.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"
      - path: opensearch-security/securityconfig/roles.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/roles.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"
      - path: opensearch-security/securityconfig/roles_mapping.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/roles_mapping.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"
      - path: opensearch-security/securityconfig/tenants.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/tenants.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"
      - path: opensearch-security/securityconfig/whitelist.yml
        type: yaml
        mode: "0640"
        group: "{{ opensearch_user }}"
        content: "{{ lookup('file', 'test/securityconfig/whitelist.yml') | from_yaml }}"
        post_command: "{{ project_security_plugin_post_command }}"

    # taken from config/log4j2.properties
    opensearch_config_log4j2_properties: |
      #
      # SPDX-License-Identifier: Apache-2.0
      #
      # The OpenSearch Contributors require contributions made to
      # this file be licensed under the Apache-2.0 license or a
      # compatible open source license.
      #
      # Modifications Copyright OpenSearch Contributors. See
      # GitHub history for details.
      #

      status = error

      appender.console.type = Console
      appender.console.name = console
      appender.console.layout.type = PatternLayout
      appender.console.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

      ######## Server JSON ############################
      appender.rolling.type = RollingFile
      appender.rolling.name = rolling
      appender.rolling.fileName = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}_server.json
      appender.rolling.layout.type = OpenSearchJsonLayout
      appender.rolling.layout.type_name = server

      appender.rolling.filePattern = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}-%d{yyyy-MM-dd}-%i.json.gz
      appender.rolling.policies.type = Policies
      appender.rolling.policies.time.type = TimeBasedTriggeringPolicy
      appender.rolling.policies.time.interval = 1
      appender.rolling.policies.time.modulate = true
      appender.rolling.policies.size.type = SizeBasedTriggeringPolicy
      appender.rolling.policies.size.size = 128MB
      appender.rolling.strategy.type = DefaultRolloverStrategy
      appender.rolling.strategy.fileIndex = nomax
      appender.rolling.strategy.action.type = Delete
      appender.rolling.strategy.action.basepath = ${sys:opensearch.logs.base_path}
      appender.rolling.strategy.action.condition.type = IfFileName
      appender.rolling.strategy.action.condition.glob = ${sys:opensearch.logs.cluster_name}-*
      appender.rolling.strategy.action.condition.nested_condition.type = IfAccumulatedFileSize
      appender.rolling.strategy.action.condition.nested_condition.exceeds = 2GB
      ################################################
      ######## Server -  old style pattern ###########
      appender.rolling_old.type = RollingFile
      appender.rolling_old.name = rolling_old
      appender.rolling_old.fileName = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}.log
      appender.rolling_old.layout.type = PatternLayout
      appender.rolling_old.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

      appender.rolling_old.filePattern = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}-%d{yyyy-MM-dd}-%i.log.gz
      appender.rolling_old.policies.type = Policies
      appender.rolling_old.policies.time.type = TimeBasedTriggeringPolicy
      appender.rolling_old.policies.time.interval = 1
      appender.rolling_old.policies.time.modulate = true
      appender.rolling_old.policies.size.type = SizeBasedTriggeringPolicy
      appender.rolling_old.policies.size.size = 128MB
      appender.rolling_old.strategy.type = DefaultRolloverStrategy
      appender.rolling_old.strategy.fileIndex = nomax
      appender.rolling_old.strategy.action.type = Delete
      appender.rolling_old.strategy.action.basepath = ${sys:opensearch.logs.base_path}
      appender.rolling_old.strategy.action.condition.type = IfFileName
      appender.rolling_old.strategy.action.condition.glob = ${sys:opensearch.logs.cluster_name}-*
      appender.rolling_old.strategy.action.condition.nested_condition.type = IfAccumulatedFileSize
      appender.rolling_old.strategy.action.condition.nested_condition.exceeds = 2GB
      ################################################

      rootLogger.level = info
      rootLogger.appenderRef.console.ref = console
      rootLogger.appenderRef.rolling.ref = rolling
      rootLogger.appenderRef.rolling_old.ref = rolling_old

      ######## Deprecation JSON #######################
      appender.deprecation_rolling.type = RollingFile
      appender.deprecation_rolling.name = deprecation_rolling
      appender.deprecation_rolling.fileName = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}_deprecation.json
      appender.deprecation_rolling.layout.type = OpenSearchJsonLayout
      appender.deprecation_rolling.layout.type_name = deprecation
      appender.deprecation_rolling.layout.opensearchmessagefields=x-opaque-id
      appender.deprecation_rolling.filter.rate_limit.type = RateLimitingFilter

      appender.deprecation_rolling.filePattern = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}_deprecation-%i.json.gz
      appender.deprecation_rolling.policies.type = Policies
      appender.deprecation_rolling.policies.size.type = SizeBasedTriggeringPolicy
      appender.deprecation_rolling.policies.size.size = 1GB
      appender.deprecation_rolling.strategy.type = DefaultRolloverStrategy
      appender.deprecation_rolling.strategy.max = 4

      appender.header_warning.type = HeaderWarningAppender
      appender.header_warning.name = header_warning
      #################################################
      ######## Deprecation -  old style pattern #######
      appender.deprecation_rolling_old.type = RollingFile
      appender.deprecation_rolling_old.name = deprecation_rolling_old
      appender.deprecation_rolling_old.fileName = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}_deprecation.log
      appender.deprecation_rolling_old.layout.type = PatternLayout
      appender.deprecation_rolling_old.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

      appender.deprecation_rolling_old.filePattern = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}\
        _deprecation-%i.log.gz
      appender.deprecation_rolling_old.policies.type = Policies
      appender.deprecation_rolling_old.policies.size.type = SizeBasedTriggeringPolicy
      appender.deprecation_rolling_old.policies.size.size = 1GB
      appender.deprecation_rolling_old.strategy.type = DefaultRolloverStrategy
      appender.deprecation_rolling_old.strategy.max = 4
      #################################################
      logger.deprecation.name = org.opensearch.deprecation
      logger.deprecation.level = deprecation
      logger.deprecation.appenderRef.deprecation_rolling.ref = deprecation_rolling
      logger.deprecation.appenderRef.deprecation_rolling_old.ref = deprecation_rolling_old
      logger.deprecation.appenderRef.header_warning.ref = header_warning
      logger.deprecation.additivity = false

      ######## Search slowlog JSON ####################
      appender.index_search_slowlog_rolling.type = RollingFile
      appender.index_search_slowlog_rolling.name = index_search_slowlog_rolling
      appender.index_search_slowlog_rolling.fileName = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs\
        .cluster_name}_index_search_slowlog.json
      appender.index_search_slowlog_rolling.layout.type = OpenSearchJsonLayout
      appender.index_search_slowlog_rolling.layout.type_name = index_search_slowlog
      appender.index_search_slowlog_rolling.layout.opensearchmessagefields=message,took,took_millis,total_hits,types,stats,search_type,total_shards,source,id

      appender.index_search_slowlog_rolling.filePattern = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs\
        .cluster_name}_index_search_slowlog-%i.json.gz
      appender.index_search_slowlog_rolling.policies.type = Policies
      appender.index_search_slowlog_rolling.policies.size.type = SizeBasedTriggeringPolicy
      appender.index_search_slowlog_rolling.policies.size.size = 1GB
      appender.index_search_slowlog_rolling.strategy.type = DefaultRolloverStrategy
      appender.index_search_slowlog_rolling.strategy.max = 4
      #################################################
      ######## Search slowlog -  old style pattern ####
      appender.index_search_slowlog_rolling_old.type = RollingFile
      appender.index_search_slowlog_rolling_old.name = index_search_slowlog_rolling_old
      appender.index_search_slowlog_rolling_old.fileName = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}\
        _index_search_slowlog.log
      appender.index_search_slowlog_rolling_old.layout.type = PatternLayout
      appender.index_search_slowlog_rolling_old.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

      appender.index_search_slowlog_rolling_old.filePattern = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}\
        _index_search_slowlog-%i.log.gz
      appender.index_search_slowlog_rolling_old.policies.type = Policies
      appender.index_search_slowlog_rolling_old.policies.size.type = SizeBasedTriggeringPolicy
      appender.index_search_slowlog_rolling_old.policies.size.size = 1GB
      appender.index_search_slowlog_rolling_old.strategy.type = DefaultRolloverStrategy
      appender.index_search_slowlog_rolling_old.strategy.max = 4
      #################################################
      logger.index_search_slowlog_rolling.name = index.search.slowlog
      logger.index_search_slowlog_rolling.level = trace
      logger.index_search_slowlog_rolling.appenderRef.index_search_slowlog_rolling.ref = index_search_slowlog_rolling
      logger.index_search_slowlog_rolling.appenderRef.index_search_slowlog_rolling_old.ref = index_search_slowlog_rolling_old
      logger.index_search_slowlog_rolling.additivity = false

      ######## Indexing slowlog JSON ##################
      appender.index_indexing_slowlog_rolling.type = RollingFile
      appender.index_indexing_slowlog_rolling.name = index_indexing_slowlog_rolling
      appender.index_indexing_slowlog_rolling.fileName = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}\
        _index_indexing_slowlog.json
      appender.index_indexing_slowlog_rolling.layout.type = OpenSearchJsonLayout
      appender.index_indexing_slowlog_rolling.layout.type_name = index_indexing_slowlog
      appender.index_indexing_slowlog_rolling.layout.opensearchmessagefields=message,took,took_millis,doc_type,id,routing,source

      appender.index_indexing_slowlog_rolling.filePattern = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}\
        _index_indexing_slowlog-%i.json.gz
      appender.index_indexing_slowlog_rolling.policies.type = Policies
      appender.index_indexing_slowlog_rolling.policies.size.type = SizeBasedTriggeringPolicy
      appender.index_indexing_slowlog_rolling.policies.size.size = 1GB
      appender.index_indexing_slowlog_rolling.strategy.type = DefaultRolloverStrategy
      appender.index_indexing_slowlog_rolling.strategy.max = 4
      #################################################
      ######## Indexing slowlog -  old style pattern ##
      appender.index_indexing_slowlog_rolling_old.type = RollingFile
      appender.index_indexing_slowlog_rolling_old.name = index_indexing_slowlog_rolling_old
      appender.index_indexing_slowlog_rolling_old.fileName = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}\
        _index_indexing_slowlog.log
      appender.index_indexing_slowlog_rolling_old.layout.type = PatternLayout
      appender.index_indexing_slowlog_rolling_old.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

      appender.index_indexing_slowlog_rolling_old.filePattern = ${sys:opensearch.logs.base_path}${sys:file.separator}${sys:opensearch.logs.cluster_name}\
        _index_indexing_slowlog-%i.log.gz
      appender.index_indexing_slowlog_rolling_old.policies.type = Policies
      appender.index_indexing_slowlog_rolling_old.policies.size.type = SizeBasedTriggeringPolicy
      appender.index_indexing_slowlog_rolling_old.policies.size.size = 1GB
      appender.index_indexing_slowlog_rolling_old.strategy.type = DefaultRolloverStrategy
      appender.index_indexing_slowlog_rolling_old.strategy.max = 4
      #################################################

      logger.index_indexing_slowlog.name = index.indexing.slowlog.index
      logger.index_indexing_slowlog.level = trace
      logger.index_indexing_slowlog.appenderRef.index_indexing_slowlog_rolling.ref = index_indexing_slowlog_rolling
      logger.index_indexing_slowlog.appenderRef.index_indexing_slowlog_rolling_old.ref = index_indexing_slowlog_rolling_old
      logger.index_indexing_slowlog.additivity = false


    x509_certificate_debug_log: yes
    # XXX these keys were create by the following steps described at:
    # https://opensearch.github.io/for-opensearch-docs/docs/security-configuration/generate-certificates/
    #
    # here is the copy of the steps:
    #
    # Root CA
    # openssl genrsa -out root-ca-key.pem 2048
    # openssl req -new -x509 -sha256 -key root-ca-key.pem -out root-ca.pem
    #
    # Admin cert
    # openssl genrsa -out admin-key-temp.pem 2048
    # openssl pkcs8 -inform PEM -outform PEM -in admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out admin-key.pem
    # openssl req -new -key admin-key.pem -out admin.csr
    # openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out admin.pem
    #
    # Node cert
    # openssl genrsa -out node-key-temp.pem 2048
    # openssl pkcs8 -inform PEM -outform PEM -in node-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-key.pem
    # openssl req -new -key node-key.pem -out node.csr
    # openssl x509 -req -in node.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out node.pem
    #
    # Cleanup
    # rm admin-key-temp.pem admin.csr node-key-temp.pem node.csr
    x509_certificate:
      - name: node
        state: present
        public:
          path: "{{ opensearch_conf_dir }}/node.pem"
          mode: "0444"
          key: "{{ lookup('file', 'test/certs/node.pem') }}"
        secret:
          path: "{{ opensearch_conf_dir }}/node-key.pem"
          owner: "{{ opensearch_user }}"
          group: "{{ opensearch_group }}"
          mode: "0600"
          key: "{{ lookup('file', 'test/certs/node-key.pem') }}"
      - name: root-ca
        state: present
        public:
          path: "{{ opensearch_conf_dir }}/root-ca.pem"
          key: "{{ lookup('file', 'test/certs/root-ca.pem') }}"
        secret:
          path: "{{ opensearch_conf_dir }}/root-ca-key.pem"
          owner: "{{ opensearch_user }}"
          group: "{{ opensearch_group }}"
          key: "{{ lookup('file', 'test/certs/root-ca-key.pem') }}"
      - name: admin
        state: present
        public:
          path: "{{ opensearch_conf_dir }}/admin.pem"
          key: "{{ lookup('file', 'test/certs/admin.pem') }}"
        secret:
          path: "{{ opensearch_conf_dir }}/admin-key.pem"
          owner: "{{ opensearch_user }}"
          group: "{{ opensearch_group }}"
          key: "{{ lookup('file', 'test/certs/admin-key.pem') }}"

    opensearch_dashboards_config:
      opensearch.hosts: ["https://localhost:9200"]
      opensearch.ssl.verificationMode: none
      opensearch.username: "kibanaserver"
      opensearch.password: "kibanaserver"
      opensearch.requestHeadersWhitelist:
        - authorization,securitytenant
      opensearch_security.multitenancy.enabled: true
      opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
      opensearch_security.readonly_mode.roles: ["kibana_read_only"]
      # Use this setting if you are running kibana without https
      opensearch_security.cookie.secure: false
```

# License

```
Copyright (c) 2019 Tomoyuki Sakurai <y@trombik.org>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

# Author Information

Tomoyuki Sakurai <y@trombik.org>

This README was created by [qansible](https://github.com/trombik/qansible)
