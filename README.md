# `trombik.opensearch`

`ansible` role to manage `opensearch`.

The role is beta.

## For FreeBSD users

The example, not the role itself, requires my own port of
`opensearch-dashboards` for FreeBSD, which can be found at
[trombik/freebsd-ports-opensearch](https://github.com/trombik/freebsd-ports-opensearch).
The example uses [`trombik.opensearch_dashboars`](https://github.com/trombik/ansible-role-opensearch_dashboards).
However, the port and the role depend on `www/node10`, which is EoLed and
deprecated.

See [Issue 835](https://github.com/opensearch-project/OpenSearch-Dashboards/issues/835)
for the upgrade plan.

## For Debian-variants and CentOS  users

The role installs `opensearch` from the official tar archive. This
is a huge hack until when Amazon or distributions release packages.

The role does not install JDK package. The bundled JDK is used instead.

The role imports a PGP key into `root`'s keyring from the upstream project to
verify the tar file.  If you know how to verify signed file without importing
PGP key, let me know.

Some plugins do not work yet.

Changes from the default includes:

* log file is under `/var/log/opensearch`
* the application is installed under `opensearch_root_dir`. The default is `/usr/local/opensearch-dashboards`
* the user to run the application is `opensearch`

The changes will be updated when an official package is available.

The role downloads the official tar archive under `opensearch_src_dir`. The
default is `/var/dist` The directory is not just a cache directory. In
addition to the tar file, it has a PGP key, a signature file , and files to
control `ansible` tasks.

The role installs a `systemd` unit file for `opensearch`. The author is not an
expert of `systemd` in any way.

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
| `opensearch_http_host` | address or `hostname` of `opensearch`. this address must be accessible from `ansible` controller (the host on which `ansible` runs). the value is used for API access, therefore, the value must match `common name` of the certificate when TLS is used and remote host verification is enabled. otherwise, API calls in the role will fail. | `localhost` |
| `opensearch_http_port` | listen port of `opensearch`. this port must be accessible from `ansible` controller (the host on which `ansible` runs) | `9200` |
| `opensearch_http_url` | URL of HTTP interface. this URL must be accessible from `ansible` controller (the host on which `ansible` runs) | `https://{{ opensearch_http_host }}:{{ opensearch_http_port }}` |
| `opensearch_http_auth` | authentication details for API access, see below | `{}` |
| `opensearch_java_home` | `JAVA_HOME` environment variable | `{{ __opensearch_java_home }}` |
| `opensearch_extra_plugin_files` | a list of extra files for plug-ins (see below) | `[]` |
| `opensearch_include_role_x509_certificate` | if true, include `trombik.x509_certificate` during the play (`trombik.x509_certificate` must be listed in `requirements.yml`) | `yes` |
| `opensearch_wait_for_cluster_status` | wait for cluster status to be this value after starting the service. valid value includes `red`, `yellow`, `green`, and `false`. set `false` value to disable | `no` |
| `opensearch_wait_for_cluster_status_timeout` | timeout when wait for cluster status to be `opensearch_wait_for_cluster_status` | `10s` |
| `opensearch_wait_for_cluster_status_retry` | retry when wait for cluster status to be `opensearch_wait_for_cluster_status` | `3` |

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
| `enabled` | Either `yes` or `no`. When `yes`, the command is executed, not when `no` | yes |

`post_command` is primarily designed for `securityadmin.sh`.
See
[Apply changes using securityadmin.sh](https://opensearch.org/docs/latest/security-plugin/configuration/security-admin/)
for more details.

## `opensearch_http_auth`

This variable is a dict, and used as user credential when accessing
API endpoints at `opensearch_http_url`.

| Key | Description | Mandatory? |
|-----|-------------|------------|
| `client_cert` | Path to client public key in `PEM` format. When it is a relative path, the path is relative from working directory on `ansible` controller, NOT on the target machine. | no |
| `client_key`  | Path to client secret key in `PEM` format. When it is a relative path, the path is relative from working directory on `ansible` controller, NOT on the target machine. | no |
| `ca_path`     | Path to CA's public key in `PEM` format. When it is a relative path, the path is relative from working directory on `ansible` controller, NOT on the target machine. | no |
| `url_username` | User name for basic authentication | no |
| `url_password` | Password for basic authentication | no |
| `validate_certs` | verify remote certificate | no |

The role passes the variable to
[`uri`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html)
module.

`ca_path` was added in `ansible` version 2.11. `client_cert` and `client_key`
were added in `ansible` version 2.4. Make sure your `ansible` version supports
the keys. As a result, you cannot use `validate_certs: yes` when your
`ansible` version is older than 2.11 and the certificate is not signed by
a CA in the default CA bundle (in most cases, you want to have your own CA to
sign certificates because of financial costs).

Note that API calls are made from `ansible` controller. `opensearch_http_url`
must be accessible from `ansible` controller.

Files that `client_cert`, `client_key`, and `ca_path` point to must be on
`ansible` controller.

## Known issues with `opensearch_http_auth` and TLS

`opensearch` supports Basic authentication and TLS client certificate
authentication over TLS. However, in some configurations, API call fails.

The short answer is: use Basic authentication over TLS with `ca_path`. This is
the only configuration that securely works as expected.

To use TLS client authentication without user name and password, you have to
set `validate_certs` to `no`. Here is the test matrix and the results.

| Authentication method  | value of `validate_certs` | with `ca_path`? | Result  |
|------------------------|---------------------------|-----------------|---------|
| TLS client certificate | `no`                      | Yes             | Success |
| TLS client certificate | `no`                      | No              | Success |
| TLS client certificate | `yes`                     | Yes             | *Fail*  |
| TLS client certificate | `yes`                     | No              | Fail (this is expected as the client cannot validate without CA certificate) |
| Basic                  | `no`                      | Yes             | Success |
| Basic                  | `no`                      | No              | Success |
| Basic                  | `yes`                     | Yes             | Success |
| Basic                  | `yes`                     | No              | Fail (this is expected as the client cannot validate without CA certificate) |

This could be a bug in `ansible` `uri` module because `curl` works fine in
both TLS client certification and Basic authentication over TLS. For the
record, the following commands were used.

```console
curl -vv --cacert /usr/local/etc/opensearch/root-ca.pem \
    --cert /usr/local/etc/opensearch/admin.pem \
    --key /usr/local/etc/opensearch/admin-key.pem \
    https://localhost:9200
```

```console
curl -vv --user admin:admin \
    --cacert /usr/local/etc/opensearch/root-ca.pem \
    https://localhost:9200
```

## Debian

| Variable | Default |
|----------|---------|
| `__opensearch_user` | `opensearch` |
| `__opensearch_group` | `opensearch` |
| `__opensearch_log_dir` | `/var/log/opensearch` |
| `__opensearch_db_dir` | `/var/lib/opensearch` |
| `__opensearch_package` | `opensearch` |
| `__opensearch_conf_dir` | `/usr/local/opensearch/config` |
| `__opensearch_root_dir` | `/usr/local/opensearch` |
| `__opensearch_scripts_dir` | `""` |
| `__opensearch_plugins_dir` | `/usr/local/opensearch/plugins` |
| `__opensearch_plugin_command` | `/usr/local/opensearch/bin/opensearch-plugin` |
| `__opensearch_service` | `opensearch` |
| `__opensearch_java_home` | `/usr/local/opensearch/jdk` |

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
| `__opensearch_conf_dir` | `/usr/local/opensearch/config` |
| `__opensearch_root_dir` | `/usr/local/opensearch` |
| `__opensearch_scripts_dir` | `""` |
| `__opensearch_plugins_dir` | `/usr/local/opensearch/plugins` |
| `__opensearch_plugin_command` | `/usr/local/opensearch/bin/opensearch-plugin` |
| `__opensearch_service` | `opensearch` |
| `__opensearch_java_home` | `/usr/local/opensearch/jdk` |

# Dependencies

- [`trombik.x509_certificate`](https://github.com/trombik/ansible-role-x509_certificate) when `opensearch_include_role_x509_certificate` is true

# Example Playbook

An example to install:

* `opensearch`
* `opensearch-dashboards`
* `haproxy`

```yaml
---
- hosts: localhost
  pre_tasks:
    - name: Allow HTTP port
      ansible.builtin.iptables:
        chain: INPUT
        destination_port: 80
        protocol: tcp
        jump: ACCEPT
      when: ansible_os_family == 'RedHat'
  roles:
    - role: trombik.freebsd_pkg_repo
      when: ansible_os_family == "FreeBSD"
    - role: trombik.java
      # XXX the bundled jdk is used on Ubuntu and CentOS
      when: ansible_os_family == "FreeBSD"
    - role: trombik.sysctl
    - ansible-role-opensearch
    - role: trombik.opensearch_dashboards
    - role: trombik.haproxy
  vars:
    # XXX use my own package as the package in the official package tree is
    # broken. note that the package depends on node10, which is EoLed and has
    # vulnerabilities.
    freebsd_pkg_repo:
      local:
        enabled: "true"
        url: "http://pkg.i.trombik.org/{{ ansible_distribution_version | regex_replace('\\.') }}{{ ansible_architecture }}-default-default"
        mirror_type: none
        priority: 100
        state: present
    os_opensearch_extra_packages:
      FreeBSD: []
      Debian:
        - unzip
      RedHat: []
    opensearch_extra_packages: "{{ os_opensearch_extra_packages[ansible_os_family] }}"
    os_java_packages:
      FreeBSD:
        - openjdk11
        - jq
        - vim
        - tmux
        - p5-ack
      Debian:
        - openjdk-11-jdk
      RedHat:
        - java-11-openjdk-devel
    java_packages: "{{ os_java_packages[ansible_os_family] }}"
    os_sysctl:
      FreeBSD:
        kern.maxfilesperproc: 65536
        security.bsd.unprivileged_mlock: 1
      Debian:
        # see https://opensearch.org/docs/latest/opensearch/install/important-settings/
        vm.max_map_count: 262144
      RedHat:
        vm.max_map_count: 262144
    sysctl: "{{ os_sysctl[ansible_os_family] }}"
    opensearch_wait_for_cluster_status: yellow
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
      RedHat: |
        ES_PATH_CONF={{ opensearch_conf_dir }}
        ES_STARTUP_SLEEP_TIME=5
    opensearch_flags: "{{ os_opensearch_flags[ansible_os_family] }}"
    os_opensearch_jvm_options:
      FreeBSD: ""
      Debian: |
        # see opensearch-tar-install.sh
        # /usr/bin/getconf CLK_TCK`
        -Dclk.tck=100
        -Djdk.attach.allowAttachSelf=true
        -Djava.security.policy={{ opensearch_root_dir }}/plugins/opensearch-performance-analyzer/pa_config/opensearch_security.policy
      RedHat: |
        # /usr/bin/getconf CLK_TCK`
        -Dclk.tck=100
        -Djdk.attach.allowAttachSelf=true
        -Djava.security.policy={{ opensearch_root_dir }}/plugins/opensearch-performance-analyzer/pa_config/opensearch_security.policy

    os_opensearch_http_auth:
      FreeBSD:
        url_username: admin
        url_password: admin
        ca_path: "{{ role_path }}/files/test/certs/root-ca.pem"
        validate_certs: yes
      Debian:
        client_cert: "{{ role_path }}/files/test/certs/admin.pem"
        client_key: "{{ role_path }}/files/test/certs/admin-key.pem"
        # XXX the version of ansible on Ubuntu is 2.9.6. as such, ca_path
        # cannot be used.
        validate_certs: no
      RedHat:
        client_cert: "{{ role_path }}/files/test/certs/admin.pem"
        client_key: "{{ role_path }}/files/test/certs/admin-key.pem"
        validate_certs: no
    opensearch_http_auth: "{{ os_opensearch_http_auth[ansible_os_family] }}"
    opensearch_jvm_options: "{{ lookup('file', 'test/jvm_options') + os_opensearch_jvm_options[ansible_os_family] }}"
    opensearch_config:
      discovery.type: single-node
      network.publish_host: ["10.0.2.15"]
      path.data: "{{ opensearch_db_dir }}"
      http.port: "{{ opensearch_http_port }}"
      path.logs: "{{ opensearch_log_dir }}"
      node.data: "true"
      http.compression: "true"
      network.host:
        - "{{ opensearch_http_host }}"
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
        # XXX use different CN for admin_dn and nodes_dn. when admin_dn ==
        # nodes_dn, it's an error.
        - CN=Admin,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU
      plugins.security.nodes_dn:
        - CN=localhost,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU

      plugins.security.advanced_modules_enabled: false
      plugins.security.audit.type: internal_opensearch
      plugins.security.enable_snapshot_restore_privilege: true
      plugins.security.check_snapshot_restore_write_privileges: true
      plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
      plugins.security.system_indices.enabled: true
      plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opendistro-asynchronous-search-response*"]

      plugins.security.disabled: false
      cluster.routing.allocation.disk.threshold_enabled: false

    project_security_plugin_dir: "{{ opensearch_plugins_dir }}/opensearch-security"
    project_securityadmin_bin: "{{ project_security_plugin_dir }}/tools/securityadmin.sh"
    project_security_plugin_post_command:
      cmd: "{{ project_securityadmin_bin }} -icl -nhnv -cacert {{ opensearch_conf_dir }}/root-ca.pem -cert {{ opensearch_conf_dir }}/admin.pem -key {{ opensearch_conf_dir }}/admin-key.pem"
      args:
        chdir: "{{ project_security_plugin_dir }}/securityconfig"
      enabled: "{% if 1 == 1 %}yes{% else %}no{% endif %}"

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

    opensearch_config_log4j2_properties: "{{ lookup('file', 'test/log4j2_properties') }}"

    x509_certificate_debug_log: yes
    # XXX these keys were created by the following steps described at:
    # https://opensearch.org/docs/latest/security-plugin/configuration/generate-certificates/
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
    #
    # see files/test/certs/Makefile to automate these steps.
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

    # _____________________________________________opensearch-dashboards
    opensearch_dashboards_config:
      server.host: "{{ opensearch_dashboards_bind_address }}"
      server.port: "{{ opensearch_dashboards_bind_port }}"
      server.name: "OpenSearch Dashboards"
      # XXX fix the path to log in the FreeBSD package
      logging.dest: "{% if ansible_os_family == 'FreeBSD' %}/var/log/opensearch_dashboards.log{% else %}{{ opensearch_dashboards_log_file }}{% endif %}"
      logging.verbose: true
      opensearch.hosts: ["https://localhost:9200"]
      path.data: "{{ opensearch_dashboards_data_dir }}"
      opensearch.ssl.verificationMode: none
      opensearch.username: "kibanaserver"
      opensearch.password: "kibanaserver"
      opensearch_security.multitenancy.enabled: true
      opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
      opensearch_security.readonly_mode.roles: ["kibana_read_only"]
      # Use this setting if you are running kibana without https
      opensearch_security.cookie.secure: false
    # _____________________________________________haproxy
    project_backend_host: 127.0.0.1
    project_backend_port: 5601
    os_haproxy_selinux_seport:
      FreeBSD: {}
      Debian: {}
      RedHat:
        ports:
          - 80
          - 5601
        proto: tcp
        setype: http_port_t
    haproxy_selinux_seport: "{{ os_haproxy_selinux_seport[ansible_os_family] }}"
    haproxy_config: |
      global
        daemon
      {% if ansible_os_family == 'FreeBSD' %}
      # FreeBSD package does not provide default
        maxconn 4096
        log /var/run/log local0 notice
          user {{ haproxy_user }}
          group {{ haproxy_group }}
      {% elif ansible_os_family == 'Debian' %}
        log /dev/log  local0
        log /dev/log  local1 notice
        chroot {{ haproxy_chroot_dir }}
        stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
        stats timeout 30s
        user {{ haproxy_user }}
        group {{ haproxy_group }}

        # Default SSL material locations
        ca-base /etc/ssl/certs
        crt-base /etc/ssl/private

        # See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
          ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
          ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
          ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
      {% elif ansible_os_family == 'OpenBSD' %}
        log 127.0.0.1   local0 debug
        maxconn 1024
        chroot {{ haproxy_chroot_dir }}
        uid 604
        gid 604
        pidfile /var/run/haproxy.pid
      {% elif ansible_os_family == 'RedHat' %}
      log         127.0.0.1 local2
      chroot      /var/lib/haproxy
      pidfile     /var/run/haproxy.pid
      maxconn     4000
      user        haproxy
      group       haproxy
      daemon
      {% endif %}

      defaults
        log global
        mode http
        timeout connect 5s
        timeout client 10s
        timeout server 10s
        option  httplog
        option  dontlognull
        retries 3
        maxconn 2000
      {% if ansible_os_family == 'Debian' %}
        errorfile 400 /etc/haproxy/errors/400.http
        errorfile 403 /etc/haproxy/errors/403.http
        errorfile 408 /etc/haproxy/errors/408.http
        errorfile 500 /etc/haproxy/errors/500.http
        errorfile 502 /etc/haproxy/errors/502.http
        errorfile 503 /etc/haproxy/errors/503.http
        errorfile 504 /etc/haproxy/errors/504.http
      {% elif ansible_os_family == 'OpenBSD' %}
        option  redispatch
      {% endif %}

      frontend http-in
        bind *:80
        default_backend servers

      backend servers
        option forwardfor
        server server1 {{ project_backend_host }}:{{ project_backend_port }} maxconn 32 check

    os_haproxy_flags:
      FreeBSD: |
        haproxy_config="{{ haproxy_conf_file }}"
        #haproxy_flags="-q -f ${haproxy_config} -p ${pidfile}"
      Debian: |
        #CONFIG="/etc/haproxy/haproxy.cfg"
        #EXTRAOPTS="-de -m 16"
      OpenBSD: ""
      RedHat: |
        OPTIONS=""
    haproxy_flags: "{{ os_haproxy_flags[ansible_os_family] }}"
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
