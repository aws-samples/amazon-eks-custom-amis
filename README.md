# Amazon EKS Custom AMIs

This repository contains [Packer](https://packer.io/) configurations to create custom AMIs based on the [Amazon EKS optimized AMI](https://github.com/awslabs/amazon-eks-ami). The Amazon EKS Optimized AMI remains the preferred way to deploy containers on Amazon EKS. The configurations provided in this project are intended to help support scenarios where further control and customization is required on EKS AMIs.

## Support & Feedback

This project is maintained by AWS Solution Architects and Consultants. It is not part of an AWS service and best-effort support is provided by the maintainers. To post feedback, submit feature ideas, or report bugs, please use the [Issues section](https://github.com/aws-samples/amazon-eks-custom-amis/issues) of this repo. If you are interested in contributing, please see the [Contribution guide](https://github.com/aws-samples/amazon-eks-custom-amis/blob/main/CONTRIBUTING.md).

_Scripts and artifacts created by this repository do not guarantee compliance. It is up to users to review and validate for their individual use cases._

## Supported Distributions & Configurations

The following AMI distributions and configuration are supported by this repository.

| Distribution | Configuration | Architecture |         Variable File       |     Available      |
| :----------- | :------------ | :----------: | :-------------------------- | :----------------- |
| EKS AL2      | CIS Benchmark |    amd64     | `al2_amd64.pkrvars.hcl`     | :white_check_mark: |
| EKS AL2      | CIS Benchmark |    arm64     | `al2_arm64.pkrvars.hcl`     | :white_check_mark: |
| EKS AL2      | NVIDIA GPU    |    amd64     | `al2_amd64_gpu.pkrvars.hcl` | :white_check_mark: |

## Prerequisites

- [Packer](https://packer.io/) v1.7+ - [installation instructions](https://learn.hashicorp.com/tutorials/packer/get-started-install-cli)

## Build an AMI

Users will need to have a default VPC in the region where the AMI will be created, or provide a subnet ID via the `subnet_id` variable. The remaining variables are optional and can be modified to suit; either through the appropriate `*.pkrvars.hcl` file or by passing via `-var 'key=value'` on the Packer CLI. See the `variables.pkr.hcl` file for variables that are available for customization.

First, initialize the project:

```sh
packer init -upgrade .
```

To build an amd64 based architecture AMI:

```sh
packer build -var-file=al2_amd64.pkrvars.hcl -var 'subnet_id=subnet-01abc23' .
```

To build an arm64 based architecture AMI:

```sh
packer build -var-file=al2_arm64.pkrvars.hcl -var 'subnet_id=subnet-01abc23' .
```

## Use AMI

The AMI can be used with [self-managed node groups](https://docs.aws.amazon.com/eks/latest/userguide/worker.html) and [EKS managed node groups](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html) within EKS. The AMIs built in this repository use the same [bootstrap script](https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh) used in the EKS Optimized AMI. To join the cluster, run the following command on boot:

```bash
/etc/eks/bootstrap.sh <cluster name> --kubelet-extra-args '--node-labels=eks.amazonaws.com/nodegroup=<node group name>,eks.amazonaws.com/nodegroup-image=<ami id>'
```

<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_amazon-parameterstore"></a> [amazon-parameterstore](#provider\_amazon-parameterstore) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [amazon-parameterstore_amazon-parameterstore.this](https://registry.terraform.io/providers/hashicorp/amazon-parameterstore/latest/docs/data-sources/amazon-parameterstore) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_access_key"></a> [access\_key](#input\_access\_key) | The access key used to communicate with AWS | `string` | `null` | no |
| <a name="input_ami_block_device_mappings"></a> [ami\_block\_device\_mappings](#input\_ami\_block\_device\_mappings) | The block device mappings attached when booting a new instance from the AMI created | `list(map(string))` | <pre>[<br>  {<br>    "delete_on_termination": true,<br>    "device_name": "/dev/xvda",<br>    "volume_size": 10,<br>    "volume_type": "gp3"<br>  }<br>]</pre> | no |
| <a name="input_ami_description"></a> [ami\_description](#input\_ami\_description) | The description to use when creating the AMI | `string` | `"Amazon EKS Kubernetes AMI based on AmazonLinux2 OS"` | no |
| <a name="input_ami_groups"></a> [ami\_groups](#input\_ami\_groups) | A list of groups that have access to launch the resulting AMI(s). By default no groups have permission to launch the AMI. `all` will make the AMI publicly accessible. AWS currently doesn't accept any value other than `all` | `list(string)` | `null` | no |
| <a name="input_ami_name_prefix"></a> [ami\_name\_prefix](#input\_ami\_name\_prefix) | The prefix to use when creating the AMI name. i.e. - `<ami_name_prefix>-<eks_version>-<timestamp>` | `string` | `"amazon-eks"` | no |
| <a name="input_ami_org_arns"></a> [ami\_org\_arns](#input\_ami\_org\_arns) | A list of Amazon Resource Names (ARN) of AWS Organizations that have access to launch the resulting AMI(s). By default no organizations have permission to launch the AMI | `list(string)` | `null` | no |
| <a name="input_ami_ou_arns"></a> [ami\_ou\_arns](#input\_ami\_ou\_arns) | A list of Amazon Resource Names (ARN) of AWS Organizations organizational units (OU) that have access to launch the resulting AMI(s). By default no organizational units have permission to launch the AMI | `list(string)` | `null` | no |
| <a name="input_ami_regions"></a> [ami\_regions](#input\_ami\_regions) | A list of regions to copy the AMI to. Tags and attributes are copied along with the AMI. AMI copying takes time depending on the size of the AMI, but will generally take many minutes | `list(string)` | `null` | no |
| <a name="input_ami_type"></a> [ami\_type](#input\_ami\_type) | The type of AMI to create. Valid values are `amazon-linux-2` or `amazon-linux-2-arm64` | `string` | `"amazon-linux-2"` | no |
| <a name="input_ami_users"></a> [ami\_users](#input\_ami\_users) | A list of account IDs that have access to launch the resulting AMI(s). By default no additional users other than the user creating the AMI has permissions to launch it | `list(string)` | `null` | no |
| <a name="input_ami_virtualization_type"></a> [ami\_virtualization\_type](#input\_ami\_virtualization\_type) | The type of virtualization used to create the AMI. Can be one of `hvm` or `paravirtual` | `string` | `"hvm"` | no |
| <a name="input_associate_public_ip_address"></a> [associate\_public\_ip\_address](#input\_associate\_public\_ip\_address) | If using a non-default VPC, public IP addresses are not provided by default. If this is true, your new instance will get a Public IP | `bool` | `null` | no |
| <a name="input_assume_role"></a> [assume\_role](#input\_assume\_role) | If provided with a role ARN, Packer will attempt to assume this role using the supplied credentials | `map(string)` | `{}` | no |
| <a name="input_aws_polling"></a> [aws\_polling](#input\_aws\_polling) | Polling configuration for the AWS waiter. Configures the waiter for resources creation or actions like attaching volumes or importing image | `map(string)` | `{}` | no |
| <a name="input_capacity_reservation_group_arn"></a> [capacity\_reservation\_group\_arn](#input\_capacity\_reservation\_group\_arn) | Provide the EC2 Capacity Reservation Group ARN that will be used by Packer | `string` | `null` | no |
| <a name="input_capacity_reservation_id"></a> [capacity\_reservation\_id](#input\_capacity\_reservation\_id) | Provide the specific EC2 Capacity Reservation ID that will be used by Packer | `string` | `null` | no |
| <a name="input_capacity_reservation_preference"></a> [capacity\_reservation\_preference](#input\_capacity\_reservation\_preference) | Set the preference for using a capacity reservation if one exists. Either will be `open` or `none`. Defaults to `none` | `string` | `null` | no |
| <a name="input_communicator"></a> [communicator](#input\_communicator) | The communicator to use to communicate with the EC2 instance. Valid values are `none`, `ssh`, `winrm`, and `ssh+winrm` | `string` | `"ssh"` | no |
| <a name="input_custom_endpoint_ec2"></a> [custom\_endpoint\_ec2](#input\_custom\_endpoint\_ec2) | This option is useful if you use a cloud provider whose API is compatible with aws EC2 | `string` | `null` | no |
| <a name="input_decode_authorization_messages"></a> [decode\_authorization\_messages](#input\_decode\_authorization\_messages) | Enable automatic decoding of any encoded authorization (error) messages using the sts:DecodeAuthorizationMessage API | `bool` | `null` | no |
| <a name="input_deprecate_at"></a> [deprecate\_at](#input\_deprecate\_at) | The date and time to deprecate the AMI, in UTC, in the following format: YYYY-MM-DDTHH:MM:SSZ. If you specify a value for seconds, Amazon EC2 rounds the seconds to the nearest minute | `string` | `null` | no |
| <a name="input_disable_stop_instance"></a> [disable\_stop\_instance](#input\_disable\_stop\_instance) | If this is set to true, Packer will not stop the instance but will assume that you will send the stop signal yourself through your final provisioner | `bool` | `null` | no |
| <a name="input_ebs_optimized"></a> [ebs\_optimized](#input\_ebs\_optimized) | Mark instance as EBS Optimized. Default `false` | `bool` | `null` | no |
| <a name="input_eks_version"></a> [eks\_version](#input\_eks\_version) | The EKS cluster version associated with the AMI created | `string` | `"1.27"` | no |
| <a name="input_ena_support"></a> [ena\_support](#input\_ena\_support) | Enable enhanced networking (ENA but not SriovNetSupport) on HVM-compatible AMIs | `bool` | `null` | no |
| <a name="input_enable_nitro_enclave"></a> [enable\_nitro\_enclave](#input\_enable\_nitro\_enclave) | Enable support for Nitro Enclaves on the instance | `bool` | `null` | no |
| <a name="input_enable_unlimited_credits"></a> [enable\_unlimited\_credits](#input\_enable\_unlimited\_credits) | Enabling Unlimited credits allows the source instance to burst additional CPU beyond its available CPU Credits for as long as the demand exists | `bool` | `null` | no |
| <a name="input_encrypt_boot"></a> [encrypt\_boot](#input\_encrypt\_boot) | Whether or not to encrypt the resulting AMI when copying a provisioned instance to an AMI. By default, Packer will keep the encryption setting to what it was in the source image | `bool` | `null` | no |
| <a name="input_fleet_tags"></a> [fleet\_tags](#input\_fleet\_tags) | Key/value pair tags to apply tags to the fleet that is issued | `map(string)` | `null` | no |
| <a name="input_force_delete_snapshot"></a> [force\_delete\_snapshot](#input\_force\_delete\_snapshot) | Force Packer to delete snapshots associated with AMIs, which have been deregistered by force\_deregister. Default `false` | `bool` | `null` | no |
| <a name="input_force_deregister"></a> [force\_deregister](#input\_force\_deregister) | Force Packer to first deregister an existing AMI if one with the same name already exists. Default `false` | `bool` | `null` | no |
| <a name="input_iam_instance_profile"></a> [iam\_instance\_profile](#input\_iam\_instance\_profile) | The name of an IAM instance profile to launch the EC2 instance with | `string` | `null` | no |
| <a name="input_imds_support"></a> [imds\_support](#input\_imds\_support) | Enforce version of the Instance Metadata Service on the built AMI. Valid options are `unset` (legacy) and `v2.0` | `string` | `"v2.0"` | no |
| <a name="input_insecure_skip_tls_verify"></a> [insecure\_skip\_tls\_verify](#input\_insecure\_skip\_tls\_verify) | This allows skipping TLS verification of the AWS EC2 endpoint. The default is `false` | `bool` | `null` | no |
| <a name="input_instance_type"></a> [instance\_type](#input\_instance\_type) | The EC2 instance type to use while building the AMI, such as `m5.large` | `string` | `"c5.xlarge"` | no |
| <a name="input_kms_key_id"></a> [kms\_key\_id](#input\_kms\_key\_id) | ID, alias or ARN of the KMS key to use for AMI encryption. This only applies to the main `region` -- any regions the AMI gets copied to copied will be encrypted by the default EBS KMS key for that region, unless you set region-specific keys in `region_kms_key_ids` | `string` | `null` | no |
| <a name="input_launch_block_device_mappings"></a> [launch\_block\_device\_mappings](#input\_launch\_block\_device\_mappings) | The block device mappings to use when creating the AMI. If you add instance store volumes or EBS volumes in addition to the root device volume, the created AMI will contain block device mapping information for those volumes. Amazon creates snapshots of the source instance's root volume and any other EBS volumes described here. When you launch an instance from this new AMI, the instance automatically launches with these additional volumes, and will restore them from snapshots taken from the source instance | `list(map(string))` | <pre>[<br>  {<br>    "delete_on_termination": true,<br>    "device_name": "/dev/xvda",<br>    "volume_size": 10,<br>    "volume_type": "gp3"<br>  }<br>]</pre> | no |
| <a name="input_max_retries"></a> [max\_retries](#input\_max\_retries) | This is the maximum number of times an API call is retried, in the case where requests are being throttled or experiencing transient failures. The delay between the subsequent API calls increases exponentially | `number` | `null` | no |
| <a name="input_metadata_options"></a> [metadata\_options](#input\_metadata\_options) | Configures the metadata options for the instance launched | `map(string)` | <pre>{<br>  "http_endpoint": "enabled",<br>  "http_put_response_hop_limit": 1,<br>  "http_tokens": "required"<br>}</pre> | no |
| <a name="input_mfa_code"></a> [mfa\_code](#input\_mfa\_code) | The MFA TOTP code. This should probably be a user variable since it changes all the time | `string` | `null` | no |
| <a name="input_pause_before_connecting"></a> [pause\_before\_connecting](#input\_pause\_before\_connecting) | We recommend that you enable SSH or WinRM as the very last step in your guest's bootstrap script, but sometimes you may have a race condition where you need Packer to wait before attempting to connect to your guest | `string` | `null` | no |
| <a name="input_pause_before_ssm"></a> [pause\_before\_ssm](#input\_pause\_before\_ssm) | The time to wait before establishing the Session Manager session | `string` | `null` | no |
| <a name="input_placement"></a> [placement](#input\_placement) | Describes the placement of an instance | `map(string)` | `{}` | no |
| <a name="input_profile"></a> [profile](#input\_profile) | The profile to use in the shared credentials file for AWS | `string` | `null` | no |
| <a name="input_region"></a> [region](#input\_region) | The name of the region, such as us-east-1, in which to launch the EC2 instance to create the AMI | `string` | `"us-west-2"` | no |
| <a name="input_region_kms_key_ids"></a> [region\_kms\_key\_ids](#input\_region\_kms\_key\_ids) | regions to copy the ami to, along with the custom kms key id (alias or arn) to use for encryption for that region. Keys must match the regions provided in `ami_regions` | `map(string)` | `null` | no |
| <a name="input_run_tags"></a> [run\_tags](#input\_run\_tags) | Key/value pair tags to apply to the generated key-pair, security group, iam profile and role, snapshot, network interfaces and instance that is launched to create the EBS volumes. The resulting AMI will also inherit these tags | `map(string)` | `null` | no |
| <a name="input_run_volume_tags"></a> [run\_volume\_tags](#input\_run\_volume\_tags) | Tags to apply to the volumes that are launched to create the AMI. These tags are not applied to the resulting AMI | `map(string)` | `null` | no |
| <a name="input_secret_key"></a> [secret\_key](#input\_secret\_key) | The secret key used to communicate with AWS | `string` | `null` | no |
| <a name="input_security_group_filter"></a> [security\_group\_filter](#input\_security\_group\_filter) | Filters used to populate the `security_group_ids` field. `security_group_ids` take precedence over this | `list(map(string))` | `[]` | no |
| <a name="input_security_group_ids"></a> [security\_group\_ids](#input\_security\_group\_ids) | A list of security group IDs to assign to the instance. By default this is not set and Packer will automatically create a new temporary security group to allow SSH access | `list(string)` | `null` | no |
| <a name="input_session_manager_port"></a> [session\_manager\_port](#input\_session\_manager\_port) | Which port to connect the local end of the session tunnel to. If left blank, Packer will choose a port for you from available ports. This option is only used when `ssh_interface` is set `session_manager` | `number` | `null` | no |
| <a name="input_shared_credentials_file"></a> [shared\_credentials\_file](#input\_shared\_credentials\_file) | Path to a credentials file to load credentials from | `string` | `null` | no |
| <a name="input_shell_provisioner1"></a> [shell\_provisioner1](#input\_shell\_provisioner1) | Values passed to the first shell provisioner | `map` | `{}` | no |
| <a name="input_shell_provisioner2"></a> [shell\_provisioner2](#input\_shell\_provisioner2) | Values passed to the second shell provisioner | `map` | `{}` | no |
| <a name="input_shell_provisioner3"></a> [shell\_provisioner3](#input\_shell\_provisioner3) | Values passed to the third/last shell provisioner | `map` | `{}` | no |
| <a name="input_shutdown_behavior"></a> [shutdown\_behavior](#input\_shutdown\_behavior) | Automatically terminate instances on shutdown in case Packer exits ungracefully. Possible values are `stop` and `terminate`. Defaults to `stop` | `string` | `null` | no |
| <a name="input_skip_credential_validation"></a> [skip\_credential\_validation](#input\_skip\_credential\_validation) | Set to true if you want to skip validating AWS credentials before runtime | `bool` | `null` | no |
| <a name="input_skip_metadata_api_check"></a> [skip\_metadata\_api\_check](#input\_skip\_metadata\_api\_check) | Skip Metadata Api Check | `bool` | `null` | no |
| <a name="input_skip_profile_validation"></a> [skip\_profile\_validation](#input\_skip\_profile\_validation) | Whether or not to check if the IAM instance profile exists. Defaults to `false` | `bool` | `null` | no |
| <a name="input_skip_region_validation"></a> [skip\_region\_validation](#input\_skip\_region\_validation) | Set to `true` if you want to skip validation of the `ami_regions` configuration option. Default `false` | `bool` | `null` | no |
| <a name="input_skip_save_build_region"></a> [skip\_save\_build\_region](#input\_skip\_save\_build\_region) | If true, Packer will not check whether an AMI with the ami\_name exists in the region it is building in. It will use an intermediary AMI name, which it will not convert to an AMI in the build region. Default `false` | `bool` | `null` | no |
| <a name="input_snapshot_groups"></a> [snapshot\_groups](#input\_snapshot\_groups) | A list of groups that have access to create volumes from the snapshot(s). By default no groups have permission to create volumes from the snapshot(s). all will make the snapshot publicly accessible | `list(string)` | `null` | no |
| <a name="input_snapshot_tags"></a> [snapshot\_tags](#input\_snapshot\_tags) | Key/value pair tags to apply to snapshot. They will override AMI tags if already applied to snapshot | `map(string)` | `null` | no |
| <a name="input_snapshot_users"></a> [snapshot\_users](#input\_snapshot\_users) | A list of account IDs that have access to create volumes from the snapshot(s). By default no additional users other than the user creating the AMI has permissions to create volumes from the backing snapshot(s) | `list(string)` | `null` | no |
| <a name="input_sriov_support"></a> [sriov\_support](#input\_sriov\_support) | Enable enhanced networking (SriovNetSupport but not ENA) on HVM-compatible AMIs | `bool` | `null` | no |
| <a name="input_ssh_agent_auth"></a> [ssh\_agent\_auth](#input\_ssh\_agent\_auth) | If true, the local SSH agent will be used to authenticate connections to the source instance. No temporary keypair will be created, and the values of `ssh_password` and `ssh_private_key_file` will be ignored. The environment variable `SSH_AUTH_SOCK` must be set for this option to work properly | `bool` | `null` | no |
| <a name="input_ssh_bastion_agent_auth"></a> [ssh\_bastion\_agent\_auth](#input\_ssh\_bastion\_agent\_auth) | If `true`, the local SSH agent will be used to authenticate with the bastion host. Defaults to `false` | `bool` | `null` | no |
| <a name="input_ssh_bastion_certificate_file"></a> [ssh\_bastion\_certificate\_file](#input\_ssh\_bastion\_certificate\_file) | Path to user certificate used to authenticate with bastion host. The ~ can be used in path and will be expanded to the home directory of current user | `string` | `null` | no |
| <a name="input_ssh_bastion_host"></a> [ssh\_bastion\_host](#input\_ssh\_bastion\_host) | A bastion host to use for the actual SSH connection | `string` | `null` | no |
| <a name="input_ssh_bastion_interactive"></a> [ssh\_bastion\_interactive](#input\_ssh\_bastion\_interactive) | If `true`, the keyboard-interactive used to authenticate with bastion host | `bool` | `null` | no |
| <a name="input_ssh_bastion_password"></a> [ssh\_bastion\_password](#input\_ssh\_bastion\_password) | The password to use to authenticate with the bastion host | `string` | `null` | no |
| <a name="input_ssh_bastion_port"></a> [ssh\_bastion\_port](#input\_ssh\_bastion\_port) | The port of the bastion host. Defaults to `22` | `number` | `null` | no |
| <a name="input_ssh_bastion_private_key_file"></a> [ssh\_bastion\_private\_key\_file](#input\_ssh\_bastion\_private\_key\_file) | Path to a PEM encoded private key file to use to authenticate with the bastion host. The `~` can be used in path and will be expanded to the home directory of current user | `string` | `null` | no |
| <a name="input_ssh_bastion_username"></a> [ssh\_bastion\_username](#input\_ssh\_bastion\_username) | The username to connect to the bastion host | `string` | `null` | no |
| <a name="input_ssh_certificate_file"></a> [ssh\_certificate\_file](#input\_ssh\_certificate\_file) | Path to user certificate used to authenticate with SSH. The `~` can be used in path and will be expanded to the home directory of current user | `string` | `null` | no |
| <a name="input_ssh_ciphers"></a> [ssh\_ciphers](#input\_ssh\_ciphers) | This overrides the value of ciphers supported by default by Golang. The default value is `["aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"]` | `list(string)` | `null` | no |
| <a name="input_ssh_clear_authorized_keys"></a> [ssh\_clear\_authorized\_keys](#input\_ssh\_clear\_authorized\_keys) | If true, Packer will attempt to remove its temporary key from `~/.ssh/authorized_keys` and `/root/.ssh/authorized_keys` | `bool` | `null` | no |
| <a name="input_ssh_disable_agent_forwarding"></a> [ssh\_disable\_agent\_forwarding](#input\_ssh\_disable\_agent\_forwarding) | If `true`, SSH agent forwarding will be disabled. Defaults to `false` | `bool` | `null` | no |
| <a name="input_ssh_file_transfer_method"></a> [ssh\_file\_transfer\_method](#input\_ssh\_file\_transfer\_method) | How to transfer files, Secure copy (`scp` default) or SSH File Transfer Protocol (`sftp`) | `string` | `null` | no |
| <a name="input_ssh_handshake_attempts"></a> [ssh\_handshake\_attempts](#input\_ssh\_handshake\_attempts) | The number of handshakes to attempt with SSH once it can connect. This defaults to `10`, unless a `ssh_timeout` is set | `number` | `null` | no |
| <a name="input_ssh_host"></a> [ssh\_host](#input\_ssh\_host) | The address to SSH to. This usually is automatically configured by the builder | `string` | `null` | no |
| <a name="input_ssh_interface"></a> [ssh\_interface](#input\_ssh\_interface) | One of `public_ip`, `private_ip`, `public_dns`, `private_dns` or `session_manager`. If set, either the public IP address, private IP address, public DNS name or private DNS name will be used as the host for SSH. The default behavior if inside a VPC is to use the public IP address if available, otherwise the private IP address will be used. If not in a VPC the public DNS name will be used | `string` | `"public_dns"` | no |
| <a name="input_ssh_keep_alive_interval"></a> [ssh\_keep\_alive\_interval](#input\_ssh\_keep\_alive\_interval) | How often to send "keep alive" messages to the server. Set to a negative value (`-1s`) to disable. Defaults to `5s` | `string` | `null` | no |
| <a name="input_ssh_key_exchange_algorithms"></a> [ssh\_key\_exchange\_algorithms](#input\_ssh\_key\_exchange\_algorithms) | If set, Packer will override the value of key exchange (kex) algorithms supported by default by Golang. Acceptable values include: `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521`, `diffie-hellman-group14-sha1`, and `diffie-hellman-group1-sha1` | `list(string)` | `null` | no |
| <a name="input_ssh_keypair_name"></a> [ssh\_keypair\_name](#input\_ssh\_keypair\_name) | If specified, this is the key that will be used for SSH with the machine. The key must match a key pair name loaded up into the remote | `string` | `null` | no |
| <a name="input_ssh_local_tunnels"></a> [ssh\_local\_tunnels](#input\_ssh\_local\_tunnels) | A list of local tunnels to use when connecting to the host | `list(string)` | `null` | no |
| <a name="input_ssh_password"></a> [ssh\_password](#input\_ssh\_password) | A plaintext password to use to authenticate with SSH | `string` | `null` | no |
| <a name="input_ssh_port"></a> [ssh\_port](#input\_ssh\_port) | The port to connect to SSH. This defaults to `22` | `number` | `null` | no |
| <a name="input_ssh_private_key_file"></a> [ssh\_private\_key\_file](#input\_ssh\_private\_key\_file) | Path to a PEM encoded private key file to use to authenticate with SSH. The ~ can be used in path and will be expanded to the home directory of current user | `string` | `null` | no |
| <a name="input_ssh_proxy_host"></a> [ssh\_proxy\_host](#input\_ssh\_proxy\_host) | A SOCKS proxy host to use for SSH connection | `string` | `null` | no |
| <a name="input_ssh_proxy_password"></a> [ssh\_proxy\_password](#input\_ssh\_proxy\_password) | The optional password to use to authenticate with the proxy server | `string` | `null` | no |
| <a name="input_ssh_proxy_port"></a> [ssh\_proxy\_port](#input\_ssh\_proxy\_port) | A port of the SOCKS proxy. Defaults to `1080` | `number` | `null` | no |
| <a name="input_ssh_proxy_username"></a> [ssh\_proxy\_username](#input\_ssh\_proxy\_username) | The optional username to authenticate with the proxy server | `string` | `null` | no |
| <a name="input_ssh_pty"></a> [ssh\_pty](#input\_ssh\_pty) | If `true`, a PTY will be requested for the SSH connection. This defaults to `false` | `bool` | `null` | no |
| <a name="input_ssh_read_write_timeout"></a> [ssh\_read\_write\_timeout](#input\_ssh\_read\_write\_timeout) | The amount of time to wait for a remote command to end. This might be useful if, for example, packer hangs on a connection after a reboot. Example: `5m`. Disabled by default | `string` | `null` | no |
| <a name="input_ssh_remote_tunnels"></a> [ssh\_remote\_tunnels](#input\_ssh\_remote\_tunnels) | A list of remote tunnels to use when connecting to the host | `list(string)` | `null` | no |
| <a name="input_ssh_timeout"></a> [ssh\_timeout](#input\_ssh\_timeout) | The time to wait for SSH to become available. Packer uses this to determine when the machine has booted so this is usually quite long. This defaults to `5m`, unless `ssh_handshake_attempts` is set | `string` | `null` | no |
| <a name="input_ssh_username"></a> [ssh\_username](#input\_ssh\_username) | The username to connect to SSH with. Required if using SSH | `string` | `"ec2-user"` | no |
| <a name="input_subnet_filter"></a> [subnet\_filter](#input\_subnet\_filter) | Filters used to populate the subnet\_id field. `subnet_id` take precedence over this | `list(map(string))` | `[]` | no |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | f using VPC, the ID of the subnet, such as subnet-12345def, where Packer will launch the EC2 instance. This field is required if you are using an non-default VPC | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Key/value pair tags applied to the AMI | `map(string)` | `{}` | no |
| <a name="input_temporary_key_pair_bits"></a> [temporary\_key\_pair\_bits](#input\_temporary\_key\_pair\_bits) | Specifies the number of bits in the key to create. For RSA keys, the minimum size is 1024 bits and the default is 4096 bits. Generally, 3072 bits is considered sufficient | `number` | `null` | no |
| <a name="input_temporary_key_pair_type"></a> [temporary\_key\_pair\_type](#input\_temporary\_key\_pair\_type) | Specifies the type of key to create. The possible values are 'dsa', 'ecdsa', 'ed25519', or 'rsa'. Default is `rsa` | `string` | `null` | no |
| <a name="input_temporary_security_group_source_cidrs"></a> [temporary\_security\_group\_source\_cidrs](#input\_temporary\_security\_group\_source\_cidrs) | A list of IPv4 CIDR blocks to be authorized access to the instance, when packer is creating a temporary security group. The default is `[0.0.0.0/0]` | `list(string)` | `null` | no |
| <a name="input_temporary_security_group_source_public_ip"></a> [temporary\_security\_group\_source\_public\_ip](#input\_temporary\_security\_group\_source\_public\_ip) | When enabled, use public IP of the host (obtained from https://checkip.amazonaws.com) as CIDR block to be authorized access to the instance, when packer is creating a temporary security group. Defaults to `false` | `bool` | `null` | no |
| <a name="input_token"></a> [token](#input\_token) | The access token to use. This is different from the access key and secret key | `string` | `null` | no |
| <a name="input_user_data"></a> [user\_data](#input\_user\_data) | User data to apply when launching the instance | `string` | `null` | no |
| <a name="input_user_data_file"></a> [user\_data\_file](#input\_user\_data\_file) | Path to a file that will be used for the user data when launching the instance | `string` | `null` | no |
| <a name="input_vpc_filter"></a> [vpc\_filter](#input\_vpc\_filter) | Filters used to populate the `vpc_id` field. `vpc_id` take precedence over this | `list(map(string))` | `[]` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | If launching into a VPC subnet, Packer needs the VPC ID in order to create a temporary security group within the VPC. Requires `subnet_id` to be set. If this field is left blank, Packer will try to get the VPC ID from the `subnet_id` | `string` | `null` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->

## License

This library is licensed under the MIT-0 License. See the [LICENSE file](./LICENSE).
