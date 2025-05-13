# Tailscale AWS Subnet Router to RDS

This project sets up a Tailscale subnet router in AWS to provide secure private access to an RDS PostgreSQL instance from any device in your tailnet.

## Setup

### 1. Prerequisites

- You will need an [AWS IAM access key or IAM Role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) to stand up resources with Terraform or OpenTofu.

While you can just put these secrets in a `~/.aws` folder or a `terraform.tfvars` file, its a good practice to avoid putting secrets on disk unencrypted. If you have 1Password, you can use [1Password Secret References](https://developer.1password.com/docs/cli/secret-references/) so that your secrets are never stored permenantly on disk.

- You will need to generate a new ssh key that we can use to provision the AWS Instance that will serve as our tailscale subnet router.

- You will need `terraform` or `opentofu` installed.

- You will need to generate, store, and reference a [TailScale Auth Key](https://login.tailscale.com/admin/settings/keys)

- You will need to update the password in `userlist.txt` to match your `terraform.tfvars` `rds_password`.

- Do **NOT use this configuration for production**. While this is good for learning how Tailscale subnet routing works to an RDS backend, it is not security hardened, setup for HA, or provisioned in a manner consistent with production workloads. Certificates are disabled intentionally to make this point abundantly clear. You've been warned.

```bash
# Set your AWS credentials
export AWS_ACCESS_KEY_ID=$(op read op://vault-name/aws-personal-access-key/access_key_id)
export AWS_SECRET_ACCESS_KEY=$(op read op://vault-name/aws-personal-access-key/secret_access_key)

# Generate an SSH key for the EC2 instance if you don't have one
ssh-keygen -t rsa -b 2048 -f ~/.ssh/tailscale-rds

# Set your TailScale Auth Key
# terraform.tfvars
#...
tailscale_auth_key = "tskey-auth-1234567890"
# or with 1Password
tailscale_auth_key = $(op read op://vault-name/tailscale-auth-key/credential)
```

### 2. Deploy

```bash
tofu init
tofu plan
tofu apply -auto-approve
```

### 3. Configure Split DNS in Tailscale

After setting up the infrastructure, you need to configure split DNS in Tailscale:

1. Go to [Tailscale Admin Console DNS settings](https://login.tailscale.com/admin/dns)
2. Add a new DNS nameserver:
   - **Nameserver IP**: 172.16.0.2 (your VPC CIDR base + 2)
   - **Restrict to domains**: us-west-2.rds.amazonaws.com
     ...or whichever datacenter sub-domains you are using
3. Save changes

### 4. Approve Route Advertising

For devices you can't install Tailscale on, you need to [approve the routes in the Tailscale admin UI](https://login.tailscale.com/admin/machines).
- You will see a `Subnets !` badge on the machine you set up. This indicates it is advertising routes but hasn't been approved.
- Click the `...` next to the machine
- Click the checkbox and click save.
- Now the `!` will be removed from the `Subnets` badge, indicating that the advertised routes are approved.

You can also accept routes on client with Tailscale installed:

```bash
tailscale set --accept-routes=true
```

### 5. Verify Connectivity

Run the verification script to test the connection:
```bash
./verify_tailscale_routing.sh <rds_endpoint> postgres <password> <subnet_router_ip>
```

```bash
» Verifying Tailscale subnet router --> RDS connection
✓ Verified local Tailscale installation.
...
» Verifying PostgreSQL connection
✓ Verified PostgreSQL connection

✓ All tests passed! Your Tailscale subnet router to RDS is working.
```

## Cleanup

```bash
tofu destroy -auto-approve
```

## Additional Resources

- [Tailscale: Subnet Routers](https://tailscale.com/kb/1019/subnets)
- [Tailscale: AWS RDS](https://tailscale.com/kb/1235/rds-aws/)
- [Tailscale: High Availability](https://tailscale.com/kb/1115/high-availability)
- [AWS RDS PostgreSQL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_PostgreSQL.html)
- [PgBouncer Documentation](https://www.pgbouncer.org/usage.html)
- [RDS Parameter List](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.PostgreSQL.CommonDBATasks.Parameters.html)
- [Terraform AWS VPC Provider](https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest)
- [Terraform AWS RDS Module Provider](https://registry.terraform.io/modules/terraform-aws-modules/rds/aws/latest#input_parameters)
- [Tailscale Site-to-Site VPN Example (Terraform)](https://github.com/tailscale/terraform-aws-tailscale-site2sitevpn/tree/main)