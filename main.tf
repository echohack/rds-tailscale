terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

data "aws_region" "current" {}

variable "aws_account" { 
  type = string 
}

variable "rds_password" { 
  type = string
} 

variable "tailscale_auth_key" {
  type = string
}

resource "aws_key_pair" "ssh_key" { 
  key_name = "rds-ssh-init"
  public_key = file("~/.ssh/tailscale-rds.pub")
}

module "vpc" { 
  source = "terraform-aws-modules/vpc/aws"

  name = "vpc-rds"
  cidr = "172.16.0.0/16"

  azs = ["us-west-2c", "us-west-2d"]
  private_subnets = ["172.16.1.0/24", "172.16.2.0/24"]
  public_subnets = ["172.16.101.0/24", "172.16.102.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true
  enable_vpn_gateway = false

  tags = { 
    Terraform = "true"
    Environment = "dev"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] // Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "ingress-ssh-all" {
    name = "allow-ssh-all"
    vpc_id = module.vpc.vpc_id 
    
    # TODO: For production use, remove SSH after setup
    ingress {
        cidr_blocks = [
          "0.0.0.0/0"
        ]
        from_port = 22
        to_port = 22
        protocol = "tcp"
    }
    
    ingress {
        cidr_blocks = [
          "0.0.0.0/0"
        ]
        from_port = 41641
        to_port = 41641
        protocol = "udp"
        description = "Tailscale direct connection"
    }

    egress {
       from_port = 0
       to_port = 0
       protocol = "-1"
       cidr_blocks = ["0.0.0.0/0"]
     }
}

module "allow_postgres" {
  source = "terraform-aws-modules/security-group/aws"

  name        = "postgres"
  vpc_id      = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 5432
      protocol    = "tcp"
      description = "postgres from VPC"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
  ]
  
  ingress_with_source_security_group_id = [
    {
      from_port                = 5432
      to_port                  = 5432
      protocol                 = "tcp"
      description              = "postgres from subnet router"
      source_security_group_id = aws_security_group.ingress-ssh-all.id
    },
  ]

  egress_with_cidr_blocks = [
    {
      rule = "all-all"
    },
  ]
}

module "db" {
  source = "terraform-aws-modules/rds/aws"
  engine = "postgres"
  engine_version = "17.5"
  major_engine_version = "17"
  family = "postgres17"
  instance_class = "db.t4g.micro"
  allocated_storage = 10
  db_name = "tailscale_test_db"
  username = "postgres"
  manage_master_user_password = false #!IMPORTANT: if set to true, password will not be used
  password = var.rds_password
  port = 5432
  subnet_ids = module.vpc.public_subnets
  vpc_security_group_ids = [module.allow_postgres.security_group_id]
  create_db_subnet_group = true
  create_db_parameter_group = true
  db_subnet_group_name = "rds-tailscale-subnet-group"
  maintenance_window = "Mon:00:00-Mon:03:00"
  backup_window      = "03:00-06:00"
  # Skip final snapshot for dev environments
  skip_final_snapshot = true
  # Disable deletion protection for dev environments
  deletion_protection = false
  identifier = "rds-tailscale-test-db"

  parameters = [
    {
      name  = "rds.force_ssl"
      value = "0"
    },
    {
      name  = "log_connections"
      value = "1"
    },
    {
      name  = "log_hostname"
      value = "1"
    },
    {
      name  = "log_min_error_statement"
      value = "debug5"
    },
    {
      name  = "log_min_messages"
      value = "debug5"
    },
    {
      name  = "log_disconnections"
      value = "1"
    }
  ]
}

resource "aws_instance" "rds-tailscale" {
  ami = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.ssh_key.key_name
  subnet_id = module.vpc.public_subnets[0]
  security_groups = [aws_security_group.ingress-ssh-all.id]
  associate_public_ip_address = true

  connection { 
    type     = "ssh"
    user     = "ubuntu"
    host     = self.public_ip
    private_key = file("~/.ssh/tailscale-rds")
  }

  provisioner "file" { 
    destination = "/tmp/pgbouncer.ini"
    content = templatefile("pgbouncer.ini.tmpl", { 
    rds_host = module.db.db_instance_address,
    rds_pass = var.rds_password,
    })
  }

  provisioner "file" { 
    destination = "/tmp/userlist.txt"
    source = "userlist.txt"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql-client",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y pgbouncer",
      "sudo apt-get install -y curl gnupg",
      "curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.gpg | sudo gpg --dearmor -o /usr/share/keyrings/tailscale-archive-keyring.gpg",
      "echo 'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu jammy main' | sudo tee /etc/apt/sources.list.d/tailscale.list",
      "sudo apt-get update",
      "sudo apt-get install -y tailscale",

      "echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.d/99-tailscale.conf",
      "echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-tailscale.conf",
      "sudo sysctl -p /etc/sysctl.d/99-tailscale.conf",
      "sudo tailscale up --authkey=${var.tailscale_auth_key} --advertise-routes=${module.vpc.vpc_cidr_block} --accept-routes --accept-dns=false --hostname=rds-tailscale",

      "sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=\"--force-confdef\" -o Dpkg::Options::=\"--force-confnew\" install -y pgbouncer",

      "sudo mkdir -p /etc/pgbouncer",
      "sudo cp /tmp/pgbouncer.ini /etc/pgbouncer/pgbouncer.ini",
      "sudo cp /tmp/userlist.txt /etc/pgbouncer/userlist.txt",

      "sudo mkdir -p /var/log/postgresql /var/run/postgresql",
      "sudo touch /var/log/postgresql/pgbouncer.log",
      "sudo chown -R postgres:postgres /etc/pgbouncer /var/log/postgresql/pgbouncer.log /var/run/postgresql",
      "sudo chmod 755 /etc/pgbouncer /var/log/postgresql /var/run/postgresql",
      "sudo chmod 644 /etc/pgbouncer/pgbouncer.ini /etc/pgbouncer/userlist.txt /var/log/postgresql/pgbouncer.log",
      "sudo chmod g+w /var/run/postgresql",
      "sudo bash -c 'grep CONF /etc/default/pgbouncer || echo \"CONF=/etc/pgbouncer/pgbouncer.ini\" | sudo tee -a /etc/default/pgbouncer'",

      "sudo systemctl daemon-reload",
      "sudo service pgbouncer restart",
    ]
  } 
}

data "external" "tailscale_port" {
  depends_on = [aws_instance.rds-tailscale]

  program = ["bash", "-c", <<-EOT
    PORT=$(ssh -i ~/.ssh/tailscale-rds -o StrictHostKeyChecking=no ubuntu@${aws_instance.rds-tailscale.public_ip} 'sudo systemctl status tailscaled | grep port=' | awk -F '--port=' '{print $2}' | awk '{print $1}')
    echo "{\"port\": \"$PORT\"}"
  EOT
  ]
}

output "tailscale_port" {
  description = "Port that Tailscale is listening on"
  value       = data.external.tailscale_port.result.port
}

output "rds_connection_test" {
  description = "Command to test RDS connection through Tailscale"
  value       = <<EOT
After applying Terraform and setting up Tailscale, verify connectivity with:

./verify_tailscale_routing.sh ${module.db.db_instance_address} postgres ${var.rds_password} ip-172-16 ${module.vpc.vpc_cidr_block}
EOT
}

output "tailscale_split_dns_setup" {
  description = "Instructions for setting up split DNS in Tailscale"
  value       = <<EOT
### IMPORTANT: Set up Split DNS in Tailscale to resolve RDS hostnames

1. Go to Tailscale Admin Console: https://login.tailscale.com/admin/dns
2. Add a new DNS nameserver with these settings:
  - Nameserver IP: ${cidrhost(module.vpc.vpc_cidr_block, 2)}
  - Restrict to domains: ${data.aws_region.current.name}.rds.amazonaws.com
3. Save the changes

This allows devices in your tailnet to resolve RDS hostnames using AWS's internal DNS server.
EOT
}
