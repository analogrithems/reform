# Reform

Reform is a tool kit developed to expand and simplify creating terraform infrastructures with the AWS provider.

(Note: While it's currently designed to work with AWS, nothing is AWS specific.  The principles would be used with GCP as well)

The Reform tool kit provides the following features.

* Secrets Management
* Templating with Jinja2
* configuration management with default support
* tooling for handling nested maps
* Securty Minded
* Enforces terraform best practices

## Requirements

Please make sure you have the following installed before install reform

* Python 3.8 - 3.11
* Terraform v1.1 - v1.6

## Getting Started
The first thing you need to do is install reform.  Currently the simplest way to do this is

```
pip install git+https://git@github.com/analogrithems/reform.git
```

The reform tool set expects your project to be structured in a particular way.  Below illustrates that layout and documents why.

Your project will look like this:

```
[projectname]/          <- project root
├── projects/
│   └──[project_name]/  <- name of a terraform project
│      ├── main.tf
│      ├── data.tf
│      ├── locals.tf
│      ├── output.tf
│      ├── variables.tf
│      └── [additional...].tf
│
├── configs/
│   ├── defaults
│   │   └── config.json   <- Default config. If you have multiple quadrants, you can put a base config here and override the values in your per quardant configs.
│   │
│   └── [quadrant]        <- Example quadrants would be {dev,stage,prod}
│       ├── config.json   <- Your normal config settings go here
│       └── secrets.json  <- Encrypted secrets go here See: cryptic
│
├── helpers/
│   └── __init__.py <- Where you can hook into inject your own secrets solution
│

```

Reform offers a project scaffold task to help you get bootstrapped.

## Tutorial
The following will walk you through making a new project and createin a vpc
What we need for reform

* aws creds
* reform installed
* setup reform
1) First we need to setup our bucket to hold state & secrets

```
$ reform mkS3Bucket -b aaron-test-us-east-1 --region us-east-1
INFO: Task: mkS3Bucket
INFO: Region: us-east-1
INFO: aaron-test-us-east-1 created in us-east-1
```

2) Now we want to create an environment or quadrant in our project.  Think of this like dev,stage,prod etc

```
$ reform create --bucket=aaron-test-us-east-1 --quadrant=dev --region=us-east-1
INFO: Task: Create project /Users/aaroncollins/Development/tim-aws-demo
INFO: Task: key_gen
None
```

Note:  You should now have this directory structure

```
$ find .
.
./.reform
./projects
./configs
./configs/dev
./configs/dev/config.json
./helpers/__init__.py
```

Note: the .reform file should be included in you VCS it’s a way reform maps quadrants to aws regions to get it’s bucket region and pri/pub keys
The S3 bucket will have a dev folder and inside that folder it will have a new pri/pub key pair.  We’ll use this later to help with secret management.

3) Now in our config file lets specify our state and stub our global configs.  Place this in config/dev/config.js

```
{
    "state": {
        "bucket": "aaron-test-us-east-1",
        "encrypt": true,
        "region": "us-east-1"
    },
    "global": {
        "vpc_name": "dev",
        "vpc_network": "10.9.0.0/16"
    }
}
```
ok, our config and state are setup.  Lets make a project called infrastructure and create a simple VPC

4) we will want to create the following files in our new project infrastructure

**projects/infrastructure/local.tf** - we use this to make locally scoped vars.  For now we’ll include a real base common_tags dict for tags we want to use on all resources

```
locals {
  common_tags = {
    project     = "infrastructure"
    terraform   = "created with terraform"
    vpc_name    = var.vpc_name
    vpc_network = var.vpc_network
  }
}
```

**projects/infrastructure/vpc.tf**

```
# Create the actual VPC
resource "aws_vpc" "main" {
  cidr_block                       = var.vpc_network
  enable_dns_hostnames             = true
  assign_generated_ipv6_cidr_block = true

  tags = merge(
    local.common_tags,
    {
      "Name" = var.vpc_name
    },
  )
}


#This creates an internet gateway that allows traffic from this vpc to hit the internet.
#In addition to an internet gateway we use also either create a natgw or give each instance a public IP
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.vpc_name}_default_igw"
    },
  )
}

#We define a default network access control list 'nacl' to define our default security rules of block everything.
#Then we should whitelist as nessecary.
resource "aws_default_network_acl" "default_nacl" {
  default_network_acl_id = aws_vpc.main.default_network_acl_id

  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.vpc_name}_default_nacl"
    },
  )
}

#Just like a VPC has a default nacl (See above) we also create a default security group for ec2 hosts and other aws resources in this vpc.
#
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.vpc_name}_default_sg"
    },
  )
}
```

**projects/infrastructure/variables.tf.tpl**

```
# Global Configs
{% for key, value in config['global'].items() %}
variable "{{key}}" {
  default = {{value | jsonify}}
}
{% endfor %}

# State Configs
{% for key, value in config['state'].items() %}

variable "{{key}}" {
  default = "{{value}}"
}

{% endfor %}
```

**projects/infrastructure/state.tf.tpl**

```
terraform {
  backend "s3" {
    bucket  = "{{config['state']['bucket']}}"
    key     = "{{project}}/{{config['state']['region']}}/{{quadrant}}"
    region  = "{{config['state']['region']}}"
    encrypt = true
  }
}
provider "aws" {
  region = "{{config['state']['region']}}"
}

#This is needed for cloudfront certs since they must come from us-east-1
provider "aws" {
	alias = "east"
  region = "us-east-1"
}
```

5)  Ok now lets try to build a plan

```
$ reform plan -q dev -p infrastrucuture
INFO: Task: Plan
INFO: Task: Init
INFO: Task: Clean
INFO: Task: Preform
preform_state.tf

Initializing the backend...

Successfully configured the backend "s3"! Terraform will automatically
use this backend unless the backend configuration changes.

Initializing provider plugins...
- Checking for available provider plugins...
- Downloading plugin for provider "aws" (hashicorp/aws) 2.64.0...

The following providers do not have any version constraints in configuration,
so the latest version was installed.

To prevent automatic upgrades to new major versions that may contain breaking
changes, it is recommended to add version = "..." constraints to the
corresponding provider blocks in configuration, with the constraint strings
suggested below.

* provider.aws: version = "~> 2.64"

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
Refreshing Terraform state in-memory prior to plan...
The refreshed state will be used to calculate this plan, but will not be
persisted to local or remote state storage.


------------------------------------------------------------------------

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_default_network_acl.default_nacl will be created
  + resource "aws_default_network_acl" "default_nacl" {
      + default_network_acl_id = (known after apply)
      + id                     = (known after apply)
      + owner_id               = (known after apply)
      + tags                   = {
          + "Name"        = "dev_default_nacl"
          + "vpc_name"    = "dev"
          + "vpc_network" = "10.9.0.0/16"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_default_security_group.default will be created
  + resource "aws_default_security_group" "default" {
      + arn                    = (known after apply)
      + description            = (known after apply)
      + egress                 = []
      + id                     = (known after apply)
      + ingress                = []
      + name                   = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"        = "dev_default_sg"
          + "vpc_name"    = "dev"
          + "vpc_network" = "10.9.0.0/16"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_internet_gateway.main will be created
  + resource "aws_internet_gateway" "main" {
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name"        = "dev_default_igw"
          + "vpc_name"    = "dev"
          + "vpc_network" = "10.9.0.0/16"
        }
      + vpc_id   = (known after apply)
    }

  # aws_vpc.main will be created
  + resource "aws_vpc" "main" {
      + arn                              = (known after apply)
      + assign_generated_ipv6_cidr_block = true
      + cidr_block                       = "10.9.0.0/16"
      + default_network_acl_id           = (known after apply)
      + default_route_table_id           = (known after apply)
      + default_security_group_id        = (known after apply)
      + dhcp_options_id                  = (known after apply)
      + enable_classiclink               = (known after apply)
      + enable_classiclink_dns_support   = (known after apply)
      + enable_dns_hostnames             = true
      + enable_dns_support               = true
      + id                               = (known after apply)
      + instance_tenancy                 = "default"
      + ipv6_association_id              = (known after apply)
      + ipv6_cidr_block                  = (known after apply)
      + main_route_table_id              = (known after apply)
      + owner_id                         = (known after apply)
      + tags                             = {
          + "Name"        = "dev"
          + "vpc_name"    = "dev"
          + "vpc_network" = "10.9.0.0/16"
        }
    }

Plan: 4 to add, 0 to change, 0 to destroy.

------------------------------------------------------------------------

This plan was saved to: tfplan

To perform exactly these actions, run the following command to apply:
    terraform apply "tfplan"

```

6) Ok, now we can apply our changes with

```
$ reform apply -q dev -p infrastructure
```

Note: in the future we can combine **plan** & **apply** by using **deploy**

The deploy task really is just an alias to plan&apply

```
$ reform deploy -q dev -p infrastructure
```
